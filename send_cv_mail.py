#!/usr/bin/env python3
import argparse
import itertools
import logging
import mimetypes
import re
import smtplib
import sys
import textwrap
import tomllib
from collections.abc import Callable, Iterable, Sequence
from email.message import EmailMessage
from email.utils import localtime, make_msgid
from logging import getLevelName
from pathlib import Path
from random import uniform
from time import sleep
from typing import Any, Final, NewType, NotRequired, TypedDict, cast

# Default config directory in user profile / home directory.
DEFAULT_CONFIG_DIR: Final = Path.home() / ".config" / "send_cv"
DEFAULT_CONFIG_PATH: Final = DEFAULT_CONFIG_DIR / "config.toml"
DEFAULT_CREDENTIALS_PATH: Final = DEFAULT_CONFIG_DIR / "credentials.toml"

# SMTP credential types.
Sender = NewType("Sender", str)
Password = NewType("Password", str)
Host = NewType("Host", str)
Port = NewType("Port", int)

# Default host and port for SMTP server.
DEFAULT_SMTP_HOST: Final = Host("smtp.gmail.com")
DEFAULT_SMTP_PORT: Final = Port(465)

# Default location for the sent log, which records recipients that were sent
# successfully so a later run can skip them.
DEFAULT_SENT_LOG_PATH: Final = (
    Path(__file__).resolve().parent / "sent_emails.log"
)

# Mail sending parameters.
# Per-operation socket timeout for the SMTP connection.
SMTP_TIMEOUT: Final = 30.0
# Range of wait times between sending emails (in seconds).
WAIT_TIMES: Final = (3.0, 9.0)
ATTEMPT_LIMIT: Final = 5  # Number of attempts to send an email.

# SMTP response codes that defer a message: the server did not accept it,
# so retrying cannot deliver a duplicate.
TEMPORARY_SMTP_CODES: Final = frozenset({421, 450, 451, 452})

# Address format accepted for senders and recipients.
EMAIL_PATTERN: Final = re.compile(
    r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
)

# Configuration file templates for auto-scaffolding.
CREDENTIALS_TEMPLATE = f"""# SMTP credentials for sending emails.
[smtp]
sender = "your.email@gmail.com"
# For Gmail, use an App Password generated at https://myaccount.google.com/apppasswords
password = "your-app-password"
host = "{DEFAULT_SMTP_HOST}"
port = {DEFAULT_SMTP_PORT}
"""


class EmailConfig(TypedDict):
    """Schema for config.toml."""

    subject: str
    message: str
    attachment_path: NotRequired[str]


CONFIG_TEMPLATE = """# Email message template configuration.
subject = "Application for Position"

# Absolute path to the CV/resume attachment (e.g. "~/Documents/cv.pdf" or "C:/Users/.../cv.pdf")
attachment_path = "~/Documents/cv.pdf"

message = \"\"\"
Dear Hiring Team,

Please find attached my CV for your consideration.

Best regards,
\"\"\"
"""

# Configure logging.
logger = logging.getLogger(__name__)


def ensure_config_scaffold(config_dir: Path) -> None:
    """
    Create configuration directory and starter template files if missing.

    Args:
        config_dir (Path): The configuration directory to scaffold.
    """
    config_dir.mkdir(parents=True, exist_ok=True)

    credentials_file = config_dir / "credentials.toml"
    if not credentials_file.exists():
        credentials_file.write_text(CREDENTIALS_TEMPLATE, encoding="utf-8")
        logger.info("Created starter credentials file at %s", credentials_file)

    config_file = config_dir / "config.toml"
    if not config_file.exists():
        config_file.write_text(CONFIG_TEMPLATE, encoding="utf-8")
        logger.info("Created starter config file at %s", config_file)


def resolve_config_path(
    explicit_path: str | None,
    filename: str,
    default_path: Path,
) -> Path:
    """
    Resolve configuration file path with cascade search.

    Precedence:
        1. Explicit CLI argument (if provided).
        2. Local directory (./filename).
        3. Default path (~/.config/send_cv/filename).

    Args:
        explicit_path (str | None): Path provided via CLI option.
        filename (str): Local filename to search for.
        default_path (Path): Fallback user config path.

    Returns:
        Path: The resolved file path.
    """
    if explicit_path:
        return Path(explicit_path).expanduser().resolve()
    local_file = Path(filename)
    if local_file.exists():
        return local_file.resolve()
    return default_path.resolve()


def load_config(config_path: Path) -> EmailConfig:
    """
    Load and validate the email template configuration file.

    Args:
        config_path (Path): Path to config.toml.

    Returns:
        EmailConfig: Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        ValueError: If required keys are missing or invalid.
    """
    if not config_path.exists():
        msg = (
            f"Configuration file not found at {config_path}. "
            "Please create it or check your --config argument."
        )
        raise FileNotFoundError(msg)

    data = parse_toml(config_path)

    if "subject" not in data or not isinstance(data["subject"], str):
        msg = f"Missing or invalid 'subject' string in {config_path}"
        raise ValueError(msg)

    if "message" not in data or not isinstance(data["message"], str):
        msg = f"Missing or invalid 'message' string in {config_path}"
        raise ValueError(msg)

    attachment_raw = data.get("attachment_path", "")
    if not isinstance(attachment_raw, str):
        msg = f"Invalid 'attachment_path' (must be a string) in {config_path}"
        raise ValueError(msg)

    return {
        "subject": data["subject"],
        "message": data["message"],
        "attachment_path": attachment_raw,
    }


def load_credentials(
    credentials_path: Path,
    *,
    require_password: bool = True,
) -> tuple[Sender, Password, Host, Port]:
    """
    Load and validate SMTP credentials from credentials.toml.

    Args:
        credentials_path (Path): Path to credentials.toml.
        require_password (bool): Whether to enforce a valid password (False for dry-run).

    Returns:
        tuple[Sender, Password, Host, Port]: Tuple of (sender, password,
            host, port).

    Raises:
        FileNotFoundError: If the credentials file does not exist.
        ValueError: If required SMTP credentials are missing or placeholders.
    """
    if not credentials_path.exists():
        msg = (
            f"Credentials file not found at {credentials_path}. "
            "Please create it or check your --credentials argument."
        )
        raise FileNotFoundError(msg)

    data = parse_toml(credentials_path)

    raw_smtp = data.get("smtp")
    if not isinstance(raw_smtp, dict):
        msg = (
            f"Credentials file {credentials_path} must contain an [smtp] table"
        )
        raise ValueError(msg)

    # TOML values are arbitrary; every field is validated before use.
    smtp_data = cast("dict[str, Any]", raw_smtp)

    raw_sender = smtp_data.get("sender")
    sender = raw_sender.strip() if isinstance(raw_sender, str) else ""
    if (
        not sender
        or sender == "your.email@gmail.com"
        or not EMAIL_PATTERN.match(sender)
    ):
        msg = (
            f"Valid sender email address must be configured in "
            f"{credentials_path} under [smtp.sender]"
        )
        raise ValueError(msg)

    raw_password = smtp_data.get("password", "")
    if not isinstance(raw_password, str):
        msg = f"Invalid password (must be a string) in {credentials_path}"
        raise ValueError(msg)
    password = raw_password.strip()
    if require_password and (
        not password or password == "your-app-password"  # noqa: S105
    ):
        msg = (
            f"Valid password must be configured in {credentials_path} "
            "under [smtp.password]"
        )
        raise ValueError(msg)

    raw_host = smtp_data.get("host", DEFAULT_SMTP_HOST)
    if not isinstance(raw_host, str):
        msg = f"Invalid SMTP host '{raw_host}' in {credentials_path}"
        raise ValueError(msg)
    host = raw_host.strip() or DEFAULT_SMTP_HOST

    raw_port = smtp_data.get("port", DEFAULT_SMTP_PORT)
    try:
        port = int(raw_port)
    except (ValueError, TypeError) as exc:
        msg = f"Invalid SMTP port '{raw_port}' in {credentials_path}"
        raise ValueError(msg) from exc
    if not 0 < port < 65536:
        msg = (
            f"SMTP port {port} is out of range (1-65535) in {credentials_path}"
        )
        raise ValueError(msg)

    return Sender(sender), Password(password), Host(host), Port(port)


def resolve_cv_path(
    explicit_cv: str | None,
    config: EmailConfig,
) -> Path:
    """
    Resolve the CV attachment path, enforcing an absolute path from config.

    Args:
        explicit_cv (str | None): Path provided via --cv CLI option.
        config (EmailConfig): Parsed email configuration.

    Returns:
        Path: The resolved absolute path to the CV file.

    Raises:
        ValueError: If no CV path is provided or if config path is relative.
        FileNotFoundError: If the CV file does not exist.
    """
    if explicit_cv:
        cv_path = Path(explicit_cv).expanduser().resolve()
    else:
        attachment_raw = config.get("attachment_path")
        if not attachment_raw or not attachment_raw.strip():
            msg = (
                "No CV attachment path specified. Provide 'attachment_path' "
                "in config.toml or pass --cv."
            )
            raise ValueError(msg)

        expanded = Path(attachment_raw).expanduser()
        if not expanded.is_absolute():
            msg = (
                f"attachment_path in config.toml must be an absolute path "
                f"(got '{attachment_raw}')"
            )
            raise ValueError(msg)
        cv_path = expanded.resolve()

    if not cv_path.exists():
        msg = f"CV attachment file not found at {cv_path}"
        raise FileNotFoundError(msg)

    return cv_path


def main() -> None:
    """Run the main logic for the script."""
    # Set up command-line argument parsing.
    args = setup_argparse().parse_args()

    batch_size = args.batch_size

    if batch_size < 1:
        msg = "Batch size must be at least 1"
        raise ValueError(msg)

    # Configure logging based on args
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=args.loglevel.upper(),
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logger.setLevel(args.loglevel.upper())
    logger.debug("Logging now set up to %s", getLevelName(logger.level))

    # Auto-scaffold default config directory and templates if missing.
    ensure_config_scaffold(DEFAULT_CONFIG_DIR)

    # Resolve and load configuration file.
    config_path = resolve_config_path(
        args.config, "config.toml", DEFAULT_CONFIG_PATH
    )
    logger.debug("Using configuration file at %s", config_path)
    config = load_config(config_path)

    # Resolve and load credentials.
    credentials_path = resolve_config_path(
        args.credentials, "credentials.toml", DEFAULT_CREDENTIALS_PATH
    )
    logger.debug("Using credentials file at %s", credentials_path)
    sender, password, host, port = load_credentials(
        credentials_path, require_password=not args.dry_run
    )

    # Handle receiver emails based on which argument was provided
    receivers: list[str]

    if args.emails:
        receivers = [email.strip() for email in args.emails]
        invalid_emails = [
            email for email in receivers if not EMAIL_PATTERN.match(email)
        ]
        if invalid_emails:
            msg = f"Invalid email address(es): {', '.join(invalid_emails)}"
            raise ValueError(msg)
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
        raise ValueError(msg)

    # Remove duplicate addresses before building or sending anything.
    receivers, duplicate_count = deduplicate_emails(receivers)
    if duplicate_count > 0:
        logger.warning(
            "Removed %d duplicate email address(es)", duplicate_count
        )

    # Drop recipients already recorded as sent, so a re-run resumes instead
    # of emailing anyone twice.
    sent_log_path = Path(args.sent_log).expanduser().resolve()
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
        sender,
        receivers,
        config=config,
        batch_size=batch_size,
    )

    # Resolve and load CV attachment.
    cv_path = resolve_cv_path(args.cv, config)
    cv_name, cv_data = load_file(cv_path)

    # Determine MIME type.
    mime_type, _ = mimetypes.guess_type(cv_path)
    content_type = mime_type or "application/octet-stream"
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
                f"Recipients={len(recipients_of(email, exclude=sender))}"
            )
        return

    # Send emails.
    sent_count = send_emails(
        sender,
        password,
        emails,
        host=host,
        port=port,
        on_sent=lambda sent: append_to_sent_log(sent_log_path, sent),
    )
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
                Configuration:
                    - Config file: Stores subject, body, and attachment_path
                      (default: ./config.toml or {DEFAULT_CONFIG_PATH})
                    - Credentials file: Stores [smtp] sender, password, host, port
                      (default: ./credentials.toml or {DEFAULT_CREDENTIALS_PATH})

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
        "--config",
        type=str,
        help="Path to the configuration file (default: ./config.toml or "
        f"{DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--credentials",
        type=str,
        help="Path to the credentials file (default: ./credentials.toml or "
        f"{DEFAULT_CREDENTIALS_PATH})",
    )
    parser.add_argument(
        "--cv",
        type=str,
        help="Path to the CV file to attach (overrides attachment_path in "
        "config.toml)",
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
        "-l",
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
    except OSError as exc:
        msg = f"Failed to read file: {exc}"
        raise OSError(msg) from exc

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
        ValueError: If the file is not valid TOML.
    """
    try:
        with Path.open(toml_path, "rb") as f:
            data = tomllib.load(f)
            logger.debug("Successfully read configuration file")
    except tomllib.TOMLDecodeError as exc:
        msg = f"Invalid TOML in {toml_path}: {exc}"
        raise ValueError(msg) from exc
    except OSError as exc:
        msg = f"Failed to read configuration file: {exc}"
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

                    if EMAIL_PATTERN.match(email):
                        valid_emails.append(email)
                    else:
                        invalid_email_line_count_for_current_file += 1
                        logger.warning(
                            "Invalid email address '%s' in file %s (line %d)",
                            email,
                            path,
                            line_num,
                        )

            if invalid_email_line_count_for_current_file > 0:
                logger.info(
                    "Skipped %d invalid email address(es) in file %s",
                    invalid_email_line_count_for_current_file,
                    path,
                )
                total_invalid_email_line_count += (
                    invalid_email_line_count_for_current_file
                )

        if total_invalid_email_line_count > 0:
            logger.info(
                "Skipped %d invalid email address(es) across all files",
                total_invalid_email_line_count,
            )

        return valid_emails
    except FileNotFoundError:
        raise
    except OSError as exc:
        msg = f"Failed to read email file: {exc}"
        raise OSError(msg) from exc


def deduplicate_emails(receivers: Iterable[str]) -> tuple[list[str], int]:
    """
    Remove duplicate emails while preserving case-insensitive first appearance.

    Args:
        receivers (Iterable[str]): Iterable of email addresses.

    Returns:
        tuple[list[str], int]: (deduplicated email list, duplicate count).
    """
    seen: set[str] = set()
    unique: list[str] = []
    duplicate_count = 0

    for email in receivers:
        normalized = email.strip().lower()
        if not normalized:
            continue
        if normalized in seen:
            duplicate_count += 1
            logger.debug("Ignoring duplicate email address: %s", email)
            continue
        seen.add(normalized)
        unique.append(email)

    return unique, duplicate_count


def load_sent_log(log_path: Path) -> set[str]:
    """
    Read the sent log and return normalized email addresses already sent.

    Non-existent log file returns an empty set.

    Args:
        log_path (Path): Path to the sent recipients log file.

    Returns:
        set[str]: Set of lowercase, stripped email addresses already sent.
    """
    if not log_path.exists():
        return set()

    sent: set[str] = set()
    try:
        with log_path.open("r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                address = line.split()[0].lower()
                sent.add(address)
    except OSError as exc:
        logger.warning(
            "Could not read sent log at %s (%s); will not skip any recipients",
            log_path,
            exc,
        )
        return set()

    return sent


def append_to_sent_log(log_path: Path, recipients: Iterable[str]) -> None:
    """
    Append sent recipient addresses to the sent log file with timestamps.

    Args:
        log_path (Path): Path to the log file.
        recipients (Iterable[str]): Accepted email addresses.
    """
    now = localtime().strftime("%Y-%m-%dT%H:%M:%S%z")
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fp:
            for recipient in recipients:
                fp.write(f"{recipient.strip()} {now}\n")
    except OSError as exc:
        logger.warning(
            "Failed to record sent recipient(s) %s in log %s: %s",
            recipients,
            log_path,
            exc,
        )


def filter_unsent(
    receivers: Iterable[str],
    sent_recipients: set[str],
) -> tuple[list[str], int]:
    """
    Filter out recipients that already appear in the sent log.

    Args:
        receivers (Iterable[str]): Candidate recipient email addresses.
        sent_recipients (set[str]): Normalized set of addresses already sent.

    Returns:
        tuple[list[str], int]: (unsent recipients, skipped count).
    """
    unsent: list[str] = []
    skipped_count = 0

    for email in receivers:
        normalized = email.strip().lower()
        if normalized in sent_recipients:
            skipped_count += 1
            logger.debug(
                "Skipping %s (already in sent log)",
                email,
            )
        else:
            unsent.append(email)

    return unsent, skipped_count


def recipients_of(
    email: EmailMessage,
    *,
    exclude: str | None = None,
) -> list[str]:
    """
    Extract all distinct recipient addresses from To and Bcc headers.

    Args:
        email (EmailMessage): The email message object.
        exclude (str | None): An address to filter out (e.g. the sender).

    Returns:
        list[str]: Cleaned list of recipient email addresses.
    """
    normalized_exclude = exclude.strip().lower() if exclude else None

    addresses: list[str] = []
    for header in ("To", "Bcc"):
        for value in email.get_all(header, []):
            for part in str(value).split(","):
                stripped = part.strip()
                if stripped and stripped.lower() != normalized_exclude:
                    addresses.append(stripped)

    return addresses


def create_emails(
    sender: Sender,
    receivers: list[str],
    *,
    config: EmailConfig,
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
        sender (Sender): Sender email address.
        receivers (list[str]): Recipient email addresses.
        config (EmailConfig): Configuration containing subject and message.
        batch_size (int): Number of recipients per message.

    Returns:
        list[EmailMessage]: Constructed email messages.

    Raises:
        ValueError: If sender or receivers are missing.
        TypeError: If required config keys are missing or invalid.
    """

    def build_single_email_message(
        sender: Sender,
        receivers: Sequence[str],
        config: EmailConfig,
    ) -> EmailMessage:
        """
        Build and return one email message.

        The function sets standard headers (From, To, Bcc, Subject,
        Reply-To, and Date) and fills the message body using values from
        the provided configuration.

        Args:
            sender (Sender): Sender email address.
            receivers (Sequence[str]): One or more recipient email addresses.
            config (EmailConfig): Configuration containing subject and message.

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
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        email["User-Agent"] = f"smtplib (Python {py_version})"
        # Set plain text content.
        email.set_content(config["message"], subtype="plain", charset="utf-8")

        return email

    emails: list[EmailMessage] = []

    for i, receiver_pack in enumerate(
        itertools.batched(receivers, batch_size, strict=False)
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


def _open_smtp_connection(
    sender: Sender,
    password: Password,
    host: Host = DEFAULT_SMTP_HOST,
    port: Port = DEFAULT_SMTP_PORT,
) -> smtplib.SMTP_SSL:
    """
    Open an authenticated SMTP connection, retrying transient failures.

    The connection attempt is retried up to ATTEMPT_LIMIT times with
    exponential backoff when the server is temporarily unavailable.
    Authentication failures are not retried.

    Args:
        sender (Sender): Sender email address.
        password (Password): Password or app-specific password for the account.
        host (Host): SMTP server hostname.
        port (Port): SMTP SSL port number.

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
            smtp = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT)
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


def _reconnect(
    smtp: smtplib.SMTP_SSL,
    sender: Sender,
    password: Password,
    host: Host,
    port: Port,
) -> smtplib.SMTP_SSL:
    """
    Close a connection and return a fresh authenticated replacement.

    Args:
        smtp (smtplib.SMTP_SSL): The connection to replace; it may already be
            broken, in which case closing it is a no-op.
        sender (Sender): Sender email address.
        password (Password): Password or app-specific password for the account.
        host (Host): SMTP server hostname.
        port (Port): SMTP SSL port number.

    Returns:
        smtplib.SMTP_SSL: A new authenticated SMTP connection.
    """
    smtp.close()
    return _open_smtp_connection(sender, password, host=host, port=port)


def _is_transient_error(exc: Exception) -> bool:
    """
    Return True if the server explicitly deferred the message.

    Only temporary rejection codes make a message safe to retry: 421 (the
    server is closing the transmission channel), 450, 451 and 452 all mean
    the message was not accepted, so a retry cannot deliver it twice. A
    refusal of every recipient is retryable only when every refusal was
    temporary.

    Transport failures (timeouts, resets, dropped connections) are not
    retryable even though they are usually transient: the message may
    already have been delivered when the failure surfaces.

    Args:
        exc (Exception): The exception raised while sending.

    Returns:
        bool: True if the message can be retried without duplicating it.
    """
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        # Raised when every recipient was refused; values are (code, error).
        codes = {code for code, _ in exc.recipients.values()}
        return bool(codes) and codes <= TEMPORARY_SMTP_CODES
    if isinstance(exc, smtplib.SMTPResponseException):
        return exc.smtp_code in TEMPORARY_SMTP_CODES
    return False


def _requires_reconnect(exc: Exception) -> bool:
    """
    Return True if a send error left the connection unusable.

    Response code 421 means the server is closing the transmission channel,
    so the connection must be re-established. SMTPServerDisconnected and
    pure transport errors (timeouts, resets) also require a fresh
    connection. Temporary codes 450, 451 and 452, and permanent rejections,
    keep the connection usable.

    Args:
        exc (Exception): The exception raised while sending.

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
    sender: Sender,
    password: Password,
    emails: Sequence[EmailMessage],
    *,
    host: Host = DEFAULT_SMTP_HOST,
    port: Port = DEFAULT_SMTP_PORT,
    on_sent: Callable[[Sequence[str]], None] | None = None,
) -> int:
    """
    Send a sequence of emails through the configured SMTP server.

    Establishes a secure SSL connection to the SMTP server,
    authenticates with the given credentials, and sends each message.

    Only temporary server rejections (codes 421, 450, 451 and 452) are
    retried, with backoff and a fresh connection when the old one is
    unusable: those codes mean the message was not accepted, so a retry
    cannot deliver it twice. Transport failures (timeouts, resets, dropped
    connections) are not retried, because the message may already have been
    delivered by the time the failure surfaces. Failed messages are skipped,
    the run continues, and every failure is logged at the end. Only
    recipients the server accepted are passed to `on_sent`.

    Recipient addresses are already set in each EmailMessage object.

    Args:
        sender (Sender): Sender email address.
        password (Password): Password or app-specific password for the account.
        emails (Sequence[EmailMessage]): EmailMessage objects to send.
        host (Host): SMTP server hostname.
        port (Port): SMTP SSL port number.
        on_sent (Callable[[Sequence[str]], None] | None): Callback invoked
            with each sent email's accepted recipient addresses right after
            a successful send, e.g. to record them in a sent log.

    Returns:
        int: The number of messages sent successfully.

    Raises:
        smtplib.SMTPAuthenticationError: If authentication fails.
        OSError: If the SMTP connection cannot be established.
    """
    smtp = _open_smtp_connection(sender, password, host=host, port=port)
    sent_messages = 0
    failures: list[tuple[list[str], str]] = []

    try:
        for i, email in enumerate(emails, start=1):
            for attempt in range(1, ATTEMPT_LIMIT + 1):
                try:
                    # sendmail returns {refused_addr: (code, error)} for
                    # recipients the server rejected while delivering to
                    # the rest; it raises if every recipient is refused.
                    refused = smtp.send_message(email)
                except (smtplib.SMTPException, OSError) as exc:
                    recipients = recipients_of(email, exclude=sender)
                    transient = _is_transient_error(exc)
                    if transient and attempt < ATTEMPT_LIMIT:
                        logger.warning(
                            "Temporary SMTP error for email %d/%d "
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
                            smtp = _reconnect(
                                smtp, sender, password, host, port
                            )
                        continue
                    # A permanent rejection, or a transport failure whose
                    # delivery state is unknown: retrying could deliver the
                    # message twice, so record the failure and move on.
                    failures.append(
                        (
                            recipients,
                            f"failed after {ATTEMPT_LIMIT} attempts: {exc}"
                            if transient
                            else str(exc),
                        )
                    )
                    if _requires_reconnect(exc):
                        smtp = _reconnect(smtp, sender, password, host, port)
                    break
                else:
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

            if i < len(emails):
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
    try:
        main()
    except smtplib.SMTPResponseException as exc:
        logger.error("SMTP error %s: %s", exc.smtp_code, exc.smtp_error)
        logger.debug("Traceback:", exc_info=True)
        sys.exit(1)
    except (ValueError, OSError) as exc:
        logger.error("%s", exc)
        logger.debug("Traceback:", exc_info=True)
        sys.exit(1)
