#!/usr/bin/python3
import argparse
import itertools
import logging
import mimetypes
import os
import random
import smtplib
import textwrap
from collections.abc import Sequence
from email.message import EmailMessage
from email.utils import localtime, make_msgid
from logging import getLevelName
from pathlib import Path
from time import sleep
from typing import Any

import tomllib

# Credentials.
SENDER = os.environ.get("SAU_MAIL")
# Google wants "app password" instead of my actual password.
PASSWORD = os.environ.get("SAU_APP_PASSWD")

# Config paths.
CV_FILE_PATH = "~/Documents/CV/TR/OzanMalciBilMuhCV.pdf"
CONFIG_FILE_PATH = "~/.config/send_cv.toml"

# Mail sending parameters.
BATCH_SIZE = 95  # Number of emails to send in a single batch.
SMTP_TIMEOUT = 30.0  # Timeout for the SMTP connection.


def main() -> None:
    """Run the main logic for the script."""
    # Set up command-line argument parsing.
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging.
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)
    logger.setLevel(args.loglevel.upper())
    logger.debug("Logging now set up to %s", getLevelName(logger.level))

    # Check if sender and password are set.
    if SENDER is None or PASSWORD is None:
        msg = "Environment variables SAU_MAIL and SAU_APP_PASSWD must be set"
        logger.error(msg)
        raise ValueError(msg)

    # Read configuration file.
    config_path = Path(CONFIG_FILE_PATH).expanduser()

    if not config_path.exists():
        msg = f"Configuration file not found at {config_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)
    logger.debug("Configuration file found at %s", config_path)

    # Read configuration file.
    config = parse_toml(config_path, logger)

    receivers: list[str] = args.receiver_emails

    # Create emails.
    emails = create_emails(
        SENDER,
        receivers,
        config,
        logger,
    )

    # Load file.
    file_path = Path(CV_FILE_PATH).expanduser()
    file_data, file_name = load_file(file_path, logger)

    # Determine MIME type.
    content_type = (
        mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    )
    maintype, subtype = content_type.split("/", 1)
    logger.debug("Determined MIME type: %s/%s", maintype, subtype)

    # Send emails.
    try:
        for i, email in enumerate(emails, 1):
            # Add attachment for each email.
            email.add_attachment(
                file_data,
                maintype=maintype,
                subtype=subtype,
                filename=file_name,
            )
            # Send individual email.
            send_email(SENDER, PASSWORD, email, logger)

            logger.info("Sent email %d/%d", i, len(emails))

            # Don't wait for the last email.
            if i < len(emails):
                # Wait a random amount of time.
                wait_time = random.uniform(0.5, 6.5)  # noqa: S311
                logger.debug("Waiting %2f seconds", wait_time)
                sleep(wait_time)
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
            "Email sent to %s with attachment %s",
            receivers,
            file_name,
        )


def setup_argparse() -> argparse.ArgumentParser:
    """
    Set up command-line argument parsing.

    Returns:
        argparse.ArgumentParser: Configured argument parser.

    """
    parser = argparse.ArgumentParser(
        description="Email sender script that sends an email with a attachment.",
        epilog=textwrap.dedent("""
                Environment variables required:
                    SAU_MAIL: The sender's email address
                    SAU_APP_PASSWD: The sender's password
                """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "receiver_emails",
        type=str,
        nargs="+",
        help="Email address of the recipient(s)",
    )

    parser.add_argument(
        "-log",
        "--loglevel",
        default="info",
        help="Provide logging level",
    )
    return parser


def load_file(file_path: Path, logger: logging.Logger) -> tuple[bytes, str]:
    """
    Load a file and return its content and name.

    Args:
        file_path (Path): Path to the file.
        logger (logging.Logger): Logger instance for logging.

    Returns:
        tuple[bytes, str]: Tuple containing the content and its name.

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

    return file_data, file_name


def parse_toml(toml_path: Path, logger: logging.Logger) -> dict[str, Any]:
    """
    Parse a TOML file and return its contents.

    Args:
        toml_path (Path): Path to the TOML file.
        logger (logging.Logger): Logger instance for logging.

    Returns:
        dict[str, Any]: Dictionary containing the parsed TOML data.

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


def create_emails(
    sender: str,
    receivers: list[str],
    config: dict[str, Any],
    logger: logging.Logger,
) -> list[EmailMessage]:
    """
    Create email messages.

    Builds email messages using the provided sender, recipients, subject, and message body.
    Sets Reply-To and Date headers automatically.

    Each email is packed into BATCH_SIZE receivers to avoid hitting limits.

    The emails are formatted as plain text.

    Args:
        sender (str): The sender's email address
        receivers (list[str]): List of recipient(s) email addresses
        config (dict[str, Any]): Configuration dictionary containing subject and message
        logger (logging.Logger): Logger object to record operation status

    Returns:
        list[EmailMessage]: A constructed list of EmailMessage objects

    Raises:
        ValueError: If the sender or receivers are not provided
        TypeError: If the config does not contain the required keys

    """

    def build_email_message(
        sender: str,
        receivers: Sequence[str],
        config: dict[str, Any],
    ) -> EmailMessage:
        """
        Build a single email message.

        Sets the From, To, Bcc, Subject, and Reply-To headers.
        Sets the Date header automatically.

        Args:
            sender (str): The sender's email address
            receivers (Sequence[str]): Sequence of recipient(s) email addresses
            config (dict[str, Any]): Configuration dictionary containing subject and message

        Returns:
            EmailMessage: A constructed EmailMessage object

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
        email["Message-ID"] = make_msgid(domain=sender.split("@")[1])
        # Set plain text content.
        email.set_content(config["message"])

        return email

    emails: list[EmailMessage] = []

    for i, receiver_pack in enumerate(
        itertools.batched(receivers, BATCH_SIZE)
    ):
        # Assign each batch a mail message.
        email = build_email_message(sender, receiver_pack, config)

        # Debug log the email headers.
        logger.debug("Email header %d:", i)
        for header, value in email.items():
            logger.debug("\t%s: %s", header, value)

        emails.append(email)

    return emails


def send_email(
    sender: str, password: str, email: EmailMessage, logger: logging.Logger
) -> None:
    """
    Send a single email using Gmail's SMTP server.

    Establishes a secure SSL connection to Gmail's SMTP server,
    authenticates with the given credentials, and transmits the email message.

    The reciever's email address is set in the EmailMessage object.

    Args:
        sender (str): The sender's email address
        password (str): The password or app-specific password for the account
        email (EmailMessage): A pre-constructed EmailMessage object to be sent
        logger (logging.Logger): Logger object to record operation status

    Returns:
        None

    Raises:
        smtplib.SMTPAuthenticationError: If authentication fails
        smtplib.SMTPException: If any SMTP-related error occurs during sending
        TimeoutError: If the connection or operations time out

    """
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=SMTP_TIMEOUT) as smtp:
        logger.debug("Established connection to SMTP server")

        smtp.login(sender, password)
        logger.debug("Successfully logged in to SMTP server")

        smtp.send_message(email)
        logger.debug("Message sent to SMTP server")


if __name__ == "__main__":
    main()
