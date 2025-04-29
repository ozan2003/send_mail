#!/usr/bin/python3
import argparse
import logging
import mimetypes
import os
import smtplib
import textwrap
from email.message import EmailMessage
from email.utils import localtime, make_msgid
from logging import getLevelName
from pathlib import Path
from typing import Any

import tomllib

# Credentials.
SENDER = os.environ.get("SAU_MAIL")
# Google wants "app password" instead of my actual password.
PASSWORD = os.environ.get("SAU_APP_PASSWD")

# Config paths.
CV_FILE_PATH = "~/Documents/CV/TR/OzanMalciBilMuhCV.pdf"
CONFIG_FILE_PATH = "~/.config/send_cv.toml"


def main():
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

    # Create message.
    email = create_email(
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

    # Add attachment.
    email.add_attachment(
        file_data, maintype=maintype, subtype=subtype, filename=file_name
    )

    # Send email.
    try:
        send_email(
            SENDER,
            PASSWORD,
            email,
            logger,
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
    Parse a TOML file and return its contents as a dictionary.

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


def create_email(
    sender: str,
    receivers: list[str],
    config: dict[str, Any],
    logger: logging.Logger,
) -> EmailMessage:
    """
    Create an email message.

    Constructs an email message with the specified sender,
    receiver(s), subject, and message body. It also sets the Reply-To header
    and the Date header.

    The email is formatted as plain text.

    Args:
        sender (str): The sender's email address
        receivers (list[str]): List of recipient(s) email addresses
        config (dict[str, Any]): Configuration dictionary containing subject and message
        logger (logging.Logger): Logger object to record operation status

    Returns:
        EmailMessage: A constructed email message object

    Raises:
        ValueError: If the sender or receivers are not provided
        TypeError: If the config does not contain the required keys

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

    # Debug log the email headers.
    logger.debug("Email headers:")
    for header, value in email.items():
        logger.debug("\t%s: %s", header, value)

    return email


def send_email(
    sender: str, password: str, email: EmailMessage, logger: logging.Logger
) -> None:
    """
    Send an email using Gmail's SMTP server.

    This function establishes a secure connection with Gmail's SMTP server,
    logs in using the provided credentials, and sends the pre-constructed email message.

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
    # Timeout is 30 seconds.
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30.0) as smtp:
        logger.debug("Established connection to SMTP server")

        smtp.login(sender, password)
        logger.debug("Successfully logged in to SMTP server")

        smtp.send_message(email)
        logger.debug("Message sent to SMTP server")


if __name__ == "__main__":
    main()
