#!/usr/bin/env python3
import argparse
import itertools
import logging
import mimetypes
import os
import re
import smtplib
import textwrap
from collections.abc import Callable, Iterable, Sequence
from email.message import EmailMessage
from email.utils import localtime, make_msgid
from logging import getLevelName
from pathlib import Path
from random import uniform
from sys import version_info
from time import sleep
from typing import Any

import tomllib
from dotenv import load_dotenv

script_dir = Path(__file__).resolve().parent

load_dotenv(script_dir / ".env")


# Credentials.
def require_env(name: str) -> str:
    """
    Return an environment variable value if it exists and is not empty.

    Args:
        name (str): Name of the environment variable.

    Returns:
        str: The environment variable value.

    Raises:
        OSError: Raised when the variable is missing or empty.
    """
    value = os.getenv(name)
    if value is None or value.strip() == "":
        msg = f"{name} environment variable not set"
        raise OSError(msg)
    return value


SENDER = require_env("SENDER")
# Password is only needed for an actual send, --dry-run must work without it.
PASSWORD = os.getenv("PASSWORD")

# Config paths.
if (cv_path := os.getenv("CV_FILE_PATH")) is not None:
    CV_FILE_PATH = os.path.expandvars(cv_path)
else:
    msg = "CV_FILE_PATH environment variable not set"
    raise OSError(msg)

if (config_path := os.getenv("CONFIG_FILE_PATH")) is not None:
    CONFIG_FILE_PATH = os.path.expandvars(config_path)
else:
    msg = "CONFIG_FILE_PATH environment variable not set"
    raise OSError(msg)

# Default location for the sent log, which records recipients that were sent
# successfully so a later run can skip them.
DEFAULT_SENT_LOG_PATH = script_dir / "sent_emails.log"

# Mail sending parameters.
SMTP_TIMEOUT = 30.0  # Per-operation socket timeout for the SMTP connection.
# Range of wait times between sending emails (in seconds).
WAIT_TIMES = (3.0, 9.0)
ATTEMPT_LIMIT = 5  # Number of attempts to send an email.

# Configure logging.
logger = logging.getLogger(__name__)


def main() -> None:
    """Run the main logic for the script."""
    # Set up command-line argument parsing.
    parser = setup_argparse()
    args = parser.parse_args()

    batch_size = args.batch_size

    if batch_size < 1:
        msg = "Batch size must be at least 1"
        logger.error(msg)
        raise ValueError(msg)

    # Configure logging based on args
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=args.loglevel.upper(),
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logger.setLevel(args.loglevel.upper())
    logger.debug("Logging now set up to %s", getLevelName(logger.level))

    # Read configuration file.
    config_path = Path(CONFIG_FILE_PATH).expanduser()

    if not config_path.exists():
        msg = f"Configuration file not found at {config_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)
    logger.debug("Configuration file found at %s", config_path)

    # Read configuration file.
    config = parse_toml(config_path)

    # Handle receiver emails based on which argument was provided
    receivers: list[str]

    if args.emails:
        receivers = args.emails
        logger.debug("Using receiver emails from command line: %s", receivers)
    elif args.emails_files:
        logger.debug("Using receiver emails from files: %s", args.emails_files)

        emails_file_paths: Iterable[Path] = (
            Path(path).expanduser() for path in args.emails_files
        )
        receivers = load_emails_from_files(emails_file_paths)

        if len(receivers) == 0:
            msg = f"No emails found in the files '{args.emails_files}'"
            raise ValueError(msg)
    else:
        # This shouldn't happen due to mutually exclusive group
        msg = "No receiver emails provided"
        logger.error(msg)
        raise ValueError(msg)

    # Remove duplicate addresses before building or sending anything.
    receivers, duplicate_count = deduplicate_emails(receivers)
    if duplicate_count > 0:
        logger.warning(
            "Removed %d duplicate email address(es)", duplicate_count
        )

    # Drop recipients already recorded as sent, so a re-run resumes instead
    # of emailing anyone twice.
    sent_log_path = Path(args.sent_log).expanduser()
    sent_recipients = load_sent_log(sent_log_path)
    if sent_recipients:
        receivers, skipped_count = filter_unsent(receivers, sent_recipients)
        if skipped_count > 0:
            logger.info(
                "Skipping %d recipient(s) already in sent log %s",
                skipped_count,
                sent_log_path,
            )

    if not receivers:
        logger.info("No unsent recipients left, nothing to do.")
        return

    # Create emails.
    emails = create_emails(
        SENDER,
        receivers,
        config=config,
        batch_size=batch_size,
    )
    # Load file.
    cv_path = Path(CV_FILE_PATH).expanduser()
    cv_name, cv_data = load_file(cv_path)

    # Determine MIME type.
    content_type = (
        mimetypes.guess_type(str(cv_path))[0] or "application/octet-stream"
    )
    maintype, subtype = content_type.split("/", 1)
    logger.debug("Determined MIME type: %s/%s", maintype, subtype)

    # Add attachment for each email.
    for email in emails:
        email.add_attachment(
            cv_data,
            maintype=maintype,
            subtype=subtype,
            filename=cv_name,
        )

    # Preview mode: print the messages without connecting to an SMTP server
    # or touching the sent log.
    if args.dry_run:
        print(
            f"[DRY RUN] Would send {len(emails)} email(s) to "
            f"{len(receivers)} recipient(s)"
        )
        print(
            f"[DRY RUN] Attachment: {cv_name} "
            f"({len(cv_data)} bytes, {maintype}/{subtype})"
        )
        for i, email in enumerate(emails, start=1):
            bcc = email.get("Bcc", "")
            print(
                f"[DRY RUN] Message {i}: To={email['To']} | "
                f"Bcc={bcc if bcc else '-'} | Subject={email['Subject']} | "
                f"Recipients={len(recipients_of(email, exclude=SENDER))}"
            )
        return

    # Send emails.
    password = require_env("PASSWORD")
    try:
        sent_count = send_emails(
            SENDER,
            password,
            emails,
            on_sent=lambda sent: append_to_sent_log(sent_log_path, sent),
        )
    except smtplib.SMTPResponseException as resp_exc:
        logger.exception(
            "SMTP Error: %s - %s",
            resp_exc.smtp_code,
            resp_exc.smtp_error,
        )
        raise
    except smtplib.SMTPException:
        logger.exception("Failed to send email due to SMTP error")
        raise
    except TimeoutError:
        logger.exception("Connection timed out while sending email")
        raise
    else:
        logger.info(
            "Sent %d of %d email(s) with attachment %s",
            sent_count,
            len(emails),
            cv_name,
        )
        logger.debug("Full recipient list: %s", receivers)


def setup_argparse() -> argparse.ArgumentParser:
    """
    Build and return the command-line argument parser.

    Returns:
        argparse.ArgumentParser: A configured argument parser.

    """
    parser = argparse.ArgumentParser(
        description="Send emails with an attachment.",
        epilog=textwrap.dedent(f"""
                Environment variables required:
                    - SENDER: The sender's email address
                    - PASSWORD: The password or app-specific password for the account (not needed with --dry-run)
                    - CV_FILE_PATH: Path to the file to be attached ({CV_FILE_PATH})
                    - CONFIG_FILE_PATH: Path to the configuration file ({CONFIG_FILE_PATH})

                Sent log:
                    Recipients are recorded after each successful send in the file
                    given by --sent-log (default: {DEFAULT_SENT_LOG_PATH}).
                    Recipients already in the log are skipped on the next run.
                """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-e",
        "--emails",
        type=str,
        nargs="+",
        help="Email address of the recipient(s)",
    )
    group.add_argument(
        "-f",
        "--emails-files",
        type=str,
        nargs="+",
        help="Path to the file(s) containing email addresses",
    )

    parser.add_argument(
        "-b",
        "--batch-size",
        type=int,
        default=3,
        help="Number of emails to send in a single batch",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Build and preview the emails without sending them",
    )
    parser.add_argument(
        "--sent-log",
        type=str,
        default=str(DEFAULT_SENT_LOG_PATH),
        help="File that records sent recipients; recipients already in it are "
        "skipped on the next run (default: %(default)s)",
    )
    parser.add_argument(
        "-log",
        "--loglevel",
        default="info",
        choices=("debug", "info", "warning", "error", "critical"),
        help="Provide logging level",
    )
    return parser


def load_file(file_path: Path) -> tuple[str, bytes]:
    """
    Read a file and return its name and contents.

    Args:
        file_path (Path): Path to the file.

    Returns:
        tuple[str, bytes]: A tuple of file name and file bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If the file cannot be read.

    """
    if not file_path.exists():
        msg = f"file not found at {file_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)

    # Read file.
    try:
        with file_path.open("rb") as fp:
            file_data = fp.read()
            file_name = file_path.name
            logger.debug("Successfully read file: %s", file_name)
    except (OSError, PermissionError) as exc:
        msg = f"Failed to read file: {exc}"
        logger.exception(msg)
        raise

    return file_name, file_data


def parse_toml(toml_path: Path) -> dict[str, Any]:
    """
    Parse a TOML file and return the resulting data.

    Args:
        toml_path (Path): Path to the TOML file.

    Returns:
        dict[str, Any]: Dictionary with parsed TOML data.

    Raises:
        OSError: If the file cannot be read.
        tomllib.TOMLDecodeError: If the file cannot be parsed.

    """
    try:
        with Path.open(toml_path, "rb") as f:
            data = tomllib.load(f)
            logger.debug("Successfully read configuration file")
    except (OSError, tomllib.TOMLDecodeError) as exc:
        msg = f"Failed to read configuration file: {exc}"
        logger.exception(msg)
        raise OSError(msg) from exc

    return data


def load_emails_from_files(file_paths: Iterable[Path]) -> list[str]:
    """
    Load email addresses from one or more files while validating their format.

    Invalid addresses are skipped and logged with file name and line number.

    Args:
        file_paths (Iterable[Path]): Paths to files containing email addresses.

    Returns:
        list[str]: List of valid email addresses.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If the file cannot be read.

    """
    email_pattern = re.compile(
        r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    )

    try:
        valid_emails: list[str] = []

        total_invalid_email_line_count = 0
        for path in file_paths:
            # Existence check for each file.
            if not path.exists():
                msg = f"Email file not found at {path}"
                logger.error(msg)
                raise FileNotFoundError(msg)
            logger.debug("Email file found at %s", path)

            invalid_email_line_count_for_current_file = 0
            with path.open("r", encoding="utf-8") as fp:
                for line_num, line in enumerate(fp, start=1):
                    email = line.strip()
                    if len(email) == 0:
                        continue  # Skip empty lines without logging.

                    if email_pattern.match(email):
                        valid_emails.append(email)
                    else:
                        invalid_email_line_count_for_current_file += 1
                        total_invalid_email_line_count += 1
                        logger.warning(
                            "Invalid email in %s at line %d: %s",
                            path,
                            line_num,
                            email,
                        )
            if invalid_email_line_count_for_current_file > 0:
                logger.warning(
                    "Found %d invalid email line(s) in %s",
                    invalid_email_line_count_for_current_file,
                    path,
                )
        logger.debug(
            "Successfully loaded %d email addresses from files",
            len(valid_emails),
        )
        if total_invalid_email_line_count > 0:
            logger.warning(
                "Total invalid email line(s) skipped across files: %d",
                total_invalid_email_line_count,
            )
        return valid_emails
    except (OSError, PermissionError) as exc:
        msg = f"Failed to read email file: {exc}"
        logger.exception(msg)
        raise OSError(msg) from exc


def deduplicate_emails(emails: Sequence[str]) -> tuple[list[str], int]:
    """
    Remove duplicate addresses while keeping the original order.

    Addresses are compared after stripping whitespace and lowercasing, so
    "A@X.com" and "a@x.com" count as the same recipient. Blank addresses are
    dropped without being counted.

    Args:
        emails (Sequence[str]): Addresses to deduplicate.

    Returns:
        tuple[list[str], int]: Unique, stripped addresses and the number of
            duplicates removed.
    """
    seen_mails: set[str] = set()
    unique_emails: list[str] = []
    duplicate_mail_n = 0

    for email in emails:
        stripped = email.strip()
        if not stripped:
            continue
        if stripped.lower() in seen_mails:
            duplicate_mail_n += 1
            continue
        seen_mails.add(stripped.lower())
        unique_emails.append(stripped)

    return unique_emails, duplicate_mail_n


def load_sent_log(sent_log_path: Path) -> set[str]:
    """
    Return the addresses recorded in a sent log.

    A missing file is treated as an empty log. Addresses are normalized by
    stripping and lowercasing so lookups match `deduplicate_emails`.

    Args:
        sent_log_path (Path): Path to the sent log file.

    Returns:
        set[str]: Normalized addresses previously recorded as sent.
    """
    sent_log_path = Path(sent_log_path)
    if not sent_log_path.exists():
        return set()

    with sent_log_path.open("r", encoding="utf-8") as fp:
        return {
            (stripped.lower()) for line in fp if (stripped := line.strip())
        }


def filter_unsent(
    receivers: Sequence[str], sent_mails: set[str]
) -> tuple[list[str], int]:
    """
    Split receivers into those not yet sent and those already in the log.

    Args:
        receivers (Sequence[str]): Recipient addresses to filter.
        sent_mails (set[str]): Normalized addresses already recorded as sent.

    Returns:
        tuple[list[str], int]: Remaining receivers and the number skipped.
    """
    remaining = [
        receiver
        for receiver in receivers
        if receiver.strip().lower() not in sent_mails
    ]
    return remaining, len(receivers) - len(remaining)


def append_to_sent_log(sent_log_path: Path, recipients: Sequence[str]) -> None:
    """
    Append recipient addresses to the sent log file.

    Each call opens the file in append mode and writes one address per line,
    so a run interrupted mid-way keeps every send that already succeeded.

    Args:
        sent_log_path (Path): Path to the sent log file.
        recipients (Sequence[str]): Addresses to record as sent.
    """
    sent_log_path = Path(sent_log_path)
    with sent_log_path.open("a", encoding="utf-8") as fp:
        for recipient in recipients:
            fp.write(f"{recipient.strip()}\n")


def recipients_of(
    email: EmailMessage, *, exclude: str | None = None
) -> list[str]:
    """
    Return the recipient addresses in an email's To and Bcc headers.

    Used for dry-run previews and for recording which recipients a sent
    message actually covered.

    Args:
        email (EmailMessage): The email message to inspect.
        exclude (str | None): Address to ignore, e.g. the sender used to
            fill a To header that would otherwise be blank.

    Returns:
        list[str]: Recipient addresses, with surrounding whitespace removed.
    """
    normalized_exclude = (
        exclude.strip().lower() if exclude is not None else None
    )

    addresses: list[str] = []
    for header in ("To", "Bcc"):
        for value in email.get_all(header, []):
            for part in str(value).split(","):
                stripped = part.strip()
                if stripped and stripped.lower() != normalized_exclude:
                    addresses.append(stripped)

    return addresses


def create_emails(
    sender: str,
    receivers: list[str],
    *,
    config: dict[str, Any],
    batch_size: int,
) -> list[EmailMessage]:
    """
    Build email messages from the sender, recipients, and config.

    Subject and message body are read from config. Reply-To and Date headers
    are set automatically. Messages are plain text.

    Recipients are grouped into batches of `batch_size` to help avoid provider
    sending limits:

        - If `batch_size` == 1, the recipient is set in the To header.
        - If `batch_size` > 1, recipients are set in Bcc and the sender is placed
      in To to avoid a blank To header, which some filters reject.

    Args:
        sender (str): Sender email address.
        receivers (list[str]): Recipient email addresses.
        config (dict[str, Any]): Configuration containing subject and message.
        batch_size (int): Number of recipients per message.

    Returns:
        list[EmailMessage]: Constructed email messages.

    Raises:
        ValueError: If sender or receivers are missing.
        TypeError: If required config keys are missing or invalid.
    """

    def build_single_email_message(
        sender: str,
        receivers: Sequence[str],
        config: dict[str, Any],
    ) -> EmailMessage:
        """
        Build and return one email message.

        The function sets standard headers (From, To, Bcc, Subject,
        Reply-To, and Date) and fills the message body using values from
        the provided configuration.

        Args:
            sender (str): Sender email address.
            receivers (Sequence[str]): One or more recipient email addresses.
            config (dict[str, Any]): Configuration containing subject and message.

        Returns:
            EmailMessage: The constructed email message.
        """
        email = EmailMessage()
        email["From"] = sender

        if len(receivers) == 1:
            email["To"] = receivers[0].strip()
        else:
            email["To"] = sender  # Some mail filters reject blank To's.
            # Don't let them see each other.
            email["Bcc"] = ",".join(map(str.strip, receivers))

        email["Subject"] = config["subject"]
        email["Reply-To"] = sender  # Add Reply-To header.
        email["Date"] = localtime()
        email["Message-ID"] = make_msgid(domain=sender.split("@", 1)[1])
        email["User-Agent"] = (
            f"smtplib (Python {version_info.major}.{version_info.minor})"
        )
        # Set plain text content.
        email.set_content(config["message"], subtype="plain", charset="utf-8")

        return email

    emails: list[EmailMessage] = []

    for i, receiver_pack in enumerate(
        itertools.batched(receivers, batch_size)
    ):
        # Assign each batch a mail message.
        # if batch size is 1, the receiver will be added to the To header.
        email = build_single_email_message(sender, receiver_pack, config)

        # Debug log the email headers.
        logger.debug("Email header %d:", i)
        for header, value in email.items():
            logger.debug("\t%s: %s", header, value)

        emails.append(email)

    return emails


def _open_smtp_connection(sender: str, password: str) -> smtplib.SMTP_SSL:
    """
    Open an authenticated SMTP connection, retrying transient failures.

    The connection attempt is retried up to ATTEMPT_LIMIT times with
    exponential backoff when the server is temporarily unavailable.
    Authentication failures are not retried.

    Args:
        sender (str): Sender email address.
        password (str): Password or app-specific password for the account.

    Returns:
        smtplib.SMTP_SSL: An authenticated SMTP connection.

    Raises:
        smtplib.SMTPAuthenticationError: If the credentials are rejected.
        OSError: If the connection could not be established.
    """
    last_exc: Exception | None = None

    for attempt in range(1, ATTEMPT_LIMIT + 1):
        smtp: smtplib.SMTP_SSL | None = None
        try:
            smtp = smtplib.SMTP_SSL(
                "smtp.gmail.com", 465, timeout=SMTP_TIMEOUT
            )
            smtp.login(sender, password)
            return smtp
        except (smtplib.SMTPException, OSError) as exc:
            if smtp is not None:
                smtp.close()
            if isinstance(exc, smtplib.SMTPAuthenticationError):
                raise
            last_exc = exc
            if attempt == ATTEMPT_LIMIT:
                break
            logger.warning(
                "Transient error connecting to SMTP server "
                "(attempt %d/%d): %s",
                attempt,
                ATTEMPT_LIMIT,
                exc,
            )
            sleep(2**attempt + uniform(0, 1))  # noqa: S311

    if last_exc is not None:
        raise last_exc
    msg = "SMTP connection failed"
    raise OSError(msg)


def _is_transient_error(exc: Exception) -> bool:
    """
    Return True if a send error may succeed when retried.

    Server responses 421, 450, 451 and 452 mean the server is temporarily
    unable to handle the message. Transport errors (timeouts, resets,
    dropped connections) are also transient.

    Args:
        exc (Exception): The exception raised while sending.

    Returns:
        bool: True if the error is transient.
    """
    if isinstance(exc, smtplib.SMTPResponseException):
        return exc.smtp_code in (421, 450, 451, 452)
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return True
    # SMTPException subclasses OSError on Python >= 3.12.4, so this
    # fallback must come after the SMTP-specific checks: what remains
    # here is pure transport errors (timeouts, resets, refused conns).
    return isinstance(exc, OSError)


def _requires_reconnect(exc: Exception) -> bool:
    """
    Return True if a transient error left the connection unusable.

    Response code 421 means the server is closing the transmission channel,
    so the connection must be re-established. SMTPServerDisconnected and
    pure transport errors (timeouts, resets) also require a fresh
    connection. Codes 450, 451 and 452 keep the connection usable.

    Args:
        exc (Exception): The transient exception raised while sending.

    Returns:
        bool: True if the connection must be re-established.
    """
    if getattr(exc, "smtp_code", None) == 421:
        return True
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return True
    return isinstance(exc, OSError) and not isinstance(
        exc, smtplib.SMTPException
    )


def send_emails(
    sender: str,
    password: str,
    emails: Sequence[EmailMessage],
    *,
    on_sent: Callable[[Sequence[str]], None] | None = None,
) -> int:
    """
    Send a sequence of emails through Gmail's SMTP server.

    Establishes a secure SSL connection to Gmail's SMTP server,
    authenticates with the given credentials, and sends each message.

    Transient failures (temporary server responses, timeouts, resets) are
    retried with backoff, reconnecting when the connection is lost. A
    permanently rejected message is skipped and the run continues, all
    failures are logged at the end. Only recipients the server accepted are
    passed to `on_sent`.

    Recipient addresses are already set in each EmailMessage object.

    Args:
        sender (str): Sender email address.
        password (str): Password or app-specific password for the account.
        emails (Sequence[EmailMessage]): EmailMessage objects to send.
        on_sent (Callable[[Sequence[str]], None] | None): Callback invoked
            with each sent email's accepted recipient addresses right after
            a successful send, e.g. to record them in a sent log.

    Returns:
        int: The number of messages sent successfully.

    Raises:
        smtplib.SMTPAuthenticationError: If authentication fails.
        OSError: If the SMTP connection cannot be established.
    """
    smtp = _open_smtp_connection(sender, password)
    sent_messages = 0
    failures: list[tuple[list[str], str]] = []

    try:
        for i, email in enumerate(emails, start=1):
            is_sent = False
            for attempt in range(1, ATTEMPT_LIMIT + 1):
                try:
                    # sendmail returns {refused_addr: (code, error)} for
                    # recipients the server rejected while delivering to
                    # the resti it raises if every recipient is refused.
                    refused = smtp.send_message(email)
                    is_sent = True
                    sent_messages += 1

                    # Log only the recipients the server accepted.
                    sent_recipients = recipients_of(email, exclude=sender)
                    if refused:
                        refused_set = {
                            address.strip().lower() for address in refused
                        }
                        sent_recipients = [
                            recipient
                            for recipient in sent_recipients
                            if recipient.strip().lower() not in refused_set
                        ]
                        for address, reason in refused.items():
                            failures.append(([address], str(reason)))

                    # Record this email's recipients right away, so a crash
                    # later in the run does not resend to them next time.
                    if sent_recipients and on_sent is not None:
                        on_sent(sent_recipients)

                    break
                except (smtplib.SMTPException, OSError) as exc:
                    recipients = recipients_of(email, exclude=sender)
                    if not _is_transient_error(exc):
                        # Permanent rejection: skip this batch and continue.
                        failures.append((recipients, str(exc)))
                        break
                    if attempt == ATTEMPT_LIMIT:
                        failures.append(
                            (
                                recipients,
                                f"failed after {ATTEMPT_LIMIT} attempts: {exc}",
                            )
                        )
                        break
                    logger.warning(
                        "Transient SMTP error for email %d/%d "
                        "(attempt %d/%d): %s",
                        i,
                        len(emails),
                        attempt,
                        ATTEMPT_LIMIT,
                        exc,
                    )
                    sleep(2**attempt + uniform(0, 1))  # noqa: S311
                    if _requires_reconnect(exc):
                        # The connection is gone or closing; retry fresh.
                        smtp.close()
                        smtp = _open_smtp_connection(sender, password)

            if is_sent and i < len(emails):
                wait_time = uniform(*WAIT_TIMES)  # noqa: S311
                logger.debug(
                    "Waiting for %.2f seconds before sending next email",
                    wait_time,
                )
                sleep(wait_time)
    finally:
        smtp.close()

    if failures:
        logger.error(
            "%d of %d email(s) failed to send", len(failures), len(emails)
        )
        for recipients, reason in failures:
            logger.error(
                "Failed to send to %s: %s", ", ".join(recipients), reason
            )

    return sent_messages


if __name__ == "__main__":
    main()
