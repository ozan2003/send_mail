#!/usr/bin/python3
"""
Email sender script that sends an email with a PDF attachment.

Usage:
    ./script_name.py <receiver_email>

Environment Variables:
    SAU_MAIL: The sender's email address
    SAU_APP_PASSWD: The sender's app password for Gmail
"""

import logging
import mimetypes
import os
import smtplib
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import tomllib

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Credentials.
sender = os.environ.get("SAU_MAIL")
# Google wants "app password" instead of my actual password.
password = os.environ.get("SAU_APP_PASSWD")

# Read configuration file.
config_path = Path("~/.config/send_cv.toml").expanduser()

if not config_path.exists():
    msg = f"Configuration file not found at {config_path}"
    logger.error(msg)
    raise FileNotFoundError(msg)


def parse_toml(toml_path: Path) -> dict[str, Any]:
    """
    Parse a TOML file and return its contents as a dictionary.

    Args:
        toml_path (Path): Path to the TOML file.

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


def main():
    if len(sys.argv) != 2:  # noqa: PLR2004
        msg = f"Usage: {sys.argv[0]} <receiver_email>"
        logger.error(msg)
        raise ValueError(msg)

    if sender is None or password is None:
        msg = "Environment variables SAU_MAIL and SAU_APP_PASSWD must be set"
        logger.error(msg)
        raise ValueError(msg)

    # Read configuration file.
    config = parse_toml(config_path)

    receiver = sys.argv[1]

    # Create message.
    email = EmailMessage()
    email["Subject"] = config["subject"]
    email["From"] = sender
    email["To"] = receiver
    email.set_content(config["message"])

    pdf_path = Path("~/Documents/CV/TR/OzanMalciBilMuhCV.pdf").expanduser()

    if not pdf_path.exists():
        msg = f"PDF file not found at {pdf_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)

    # Read PDF file.
    try:
        with pdf_path.open("rb") as pdf:
            pdf_data = pdf.read()
            pdf_name = pdf_path.name
            logger.debug("Successfully read PDF file: %s", pdf_name)
    except (OSError, PermissionError) as exc:
        msg = f"Failed to read PDF file: {exc}"
        logger.exception(msg)
        raise

    # Determine MIME type.
    content_type = (
        mimetypes.guess_type(str(pdf_path))[0] or "application/octet-stream"
    )
    maintype, subtype = content_type.split("/", 1)
    logger.debug("Determined MIME type: %s/%s", maintype, subtype)

    # Add attachment.
    email.add_attachment(
        pdf_data, maintype=maintype, subtype=subtype, filename=pdf_name
    )

    # Send email.
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            logger.debug("Established connection to SMTP server")

            smtp.login(sender, password)
            logger.debug("Successfully logged in to SMTP server")

            smtp.send_message(email)
            logger.debug("Message sent to SMTP server")
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
    else:
        logger.info("Email sent to %s with attachment %s", receiver, pdf_name)


if __name__ == "__main__":
    main()
