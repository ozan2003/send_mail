# Send mail

- Send mail with school mail.
- Reads mail subject and body from a .toml file.
- Adds the CV as an attachment.
- Sends the mail to the specified recipient(s).

## Configuration

If you want to use this script as is, you will need to configure the following:

- Mail address and password as environment variables. (default names: `SENDER` and `PASSWORD`)
- The mail subject and body in a .toml file. (`CONFIG_FILE_PATH`)
- The CV file path. (`CV_FILE_PATH`)

Refer to `-h/--help` for usage.

Run with `--dry-run` to preview the emails without sending. Sent recipients
are recorded in `sent_emails.log` (override with `--sent-log`) and skipped
on the next run.
