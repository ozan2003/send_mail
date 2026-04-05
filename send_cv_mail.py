#!/usr/bin/env python3
import argparse
import itertools
import logging
import mimetypes
import os
import re
import smtplib
import textwrap
from collections.abc import Iterable, Sequence
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
PASSWORD = require_env("PASSWORD")

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

# Mail sending parameters.
SMTP_TIMEOUT = 30.0  # Timeout for the SMTP connection.
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

    # Send emails.
    try:
        send_emails(SENDER, PASSWORD, emails)
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
            "Sent %d email(s) with attachment %s",
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
        epilog=textwrap.dedent("""
                Environment variables required:
                    - SENDER: The sender's email address
                    - PASSWORD: The password or app-specific password for the account
                    - CV_FILE_PATH: Path to the file to be attached
                    - CONFIG_FILE_PATH: Path to the configuration file
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


def send_emails(
    sender: str, password: str, emails: Sequence[EmailMessage]
) -> None:
    """
    Send a sequence of emails through Gmail's SMTP server.

    Establishes a secure SSL connection to Gmail's SMTP server,
    authenticates with the given credentials, and sends each message.

    Recipient addresses are already set in each EmailMessage object.

    Args:
        sender (str): Sender email address.
        password (str): Password or app-specific password for the account.
        emails (Sequence[EmailMessage]): EmailMessage objects to send.

    Raises:
        smtplib.SMTPAuthenticationError: If authentication fails.
        smtplib.SMTPException: If an SMTP-related error occurs while sending.
        TimeoutError: If the connection or operations time out.
        RuntimeError: If an email fails after the maximum number of attempts.

    """
    # Take wait times into account, its margin for safety.
    timeout = 2 * SMTP_TIMEOUT + len(emails) * WAIT_TIMES[1]

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=timeout) as smtp:
        logger.debug("Established connection to SMTP server")
        smtp.login(sender, password)
        logger.debug("Successfully logged in to SMTP server")

        for i, email in enumerate(emails, start=1):
            for attempt in range(1, ATTEMPT_LIMIT + 1):
                try:
                    smtp.send_message(email)

                    logger.debug("Sent email %d/%d", i, len(emails))
                    if i < len(emails):
                        wait_time = uniform(*WAIT_TIMES)  # noqa: S311
                        logger.debug(
                            "Waiting for %.2f seconds before sending next email",
                            wait_time,
                        )
                        sleep(wait_time)
                    break  # success, exit the retry loop
                except smtplib.SMTPException as exc:
                    if getattr(exc, "smtp_code", None) not in (
                        421,
                        450,
                        451,
                        452,
                    ):
                        raise
                    sleep(2**attempt + uniform(0, 1))  # noqa: S311
                    continue  # retry
            else:
                msg = f"Failed to send email to {email['To']} after {ATTEMPT_LIMIT} attempts"
                raise RuntimeError(msg)


if __name__ == "__main__":
    main()
