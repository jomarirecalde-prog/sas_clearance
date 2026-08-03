<?php

declare(strict_types=1);

namespace App\Mail;

use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;

final class PasswordResetEmail
{
    /**
     * Sends password reset email. Uses SMTP when MAIL_HOST is set and PHPMailer is available;
     * otherwise falls back to PHP mail().
     */
    public static function send(string $toEmail, string $resetUrl): bool
    {
        $fromEmail = trim((string) (getenv('MAIL_FROM_ADDRESS') ?: ''));
        if ($fromEmail === '') {
            return false;
        }

        $fromName = trim((string) (getenv('MAIL_FROM_NAME') ?: 'WPU Clearance System'));
        $subject = 'WPU Clearance - Password Reset Request';
        $safeResetUrl = htmlspecialchars($resetUrl, ENT_QUOTES, 'UTF-8');
        $htmlBody = '<p>Hello,</p>'
            . '<p>We received a password reset request for your WPU Clearance account.</p>'
            . '<p><a href="' . $safeResetUrl . '">Click here to reset your password</a></p>'
            . '<p>This link will expire in 30 minutes and can only be used once.</p>'
            . '<p>If you did not request this, please ignore this message.</p>';
        $plainBody = "Hello,\n\n"
            . "We received a password reset request for your WPU Clearance account.\n\n"
            . "Reset link: " . $resetUrl . "\n\n"
            . "This link will expire in 30 minutes and can only be used once.\n"
            . "If you did not request this, you can ignore this message.\n";

        $smtpHost = trim((string) (getenv('MAIL_HOST') ?: ''));
        if ($smtpHost !== '' && class_exists(PHPMailer::class)) {
            return self::sendViaSmtp(
                $toEmail,
                $fromEmail,
                $fromName,
                $subject,
                $plainBody,
                $htmlBody,
                $smtpHost
            );
        }

        return self::sendViaPhpMail(
            $toEmail,
            $fromEmail,
            $fromName,
            $subject,
            $plainBody,
            $htmlBody
        );
    }

    private static function sendViaSmtp(
        string $toEmail,
        string $fromEmail,
        string $fromName,
        string $subject,
        string $plainBody,
        string $htmlBody,
        string $smtpHost
    ): bool {
        try {
            $mail = new PHPMailer(true);
            $mail->isSMTP();
            $mail->Host = $smtpHost;
            $mail->Port = (int) (getenv('MAIL_PORT') ?: 587);
            $mail->CharSet = PHPMailer::CHARSET_UTF8;

            $encryption = strtolower(trim((string) (getenv('MAIL_ENCRYPTION') ?: 'tls')));
            if ($encryption === 'tls') {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            } elseif ($encryption === 'ssl') {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            } else {
                $mail->SMTPSecure = '';
                $mail->SMTPAutoTLS = false;
            }

            $user = trim((string) (getenv('MAIL_USERNAME') ?: ''));
            $pass = (string) (getenv('MAIL_PASSWORD') ?: '');
            if ($user !== '' || $pass !== '') {
                $mail->SMTPAuth = true;
                $mail->Username = $user;
                $mail->Password = $pass;
            } else {
                $mail->SMTPAuth = false;
            }

            $debugLevel = (int) (getenv('MAIL_SMTP_DEBUG') ?: 0);
            if ($debugLevel > 0) {
                $mail->SMTPDebug = $debugLevel;
            }

            $mail->setFrom($fromEmail, $fromName);
            $mail->addAddress($toEmail);
            $mail->Subject = $subject;
            $mail->isHTML(true);
            $mail->Body = $htmlBody;
            $mail->AltBody = $plainBody;

            $mail->send();

            return true;
        } catch (Exception) {
            return false;
        }
    }

    private static function sendViaPhpMail(
        string $toEmail,
        string $fromEmail,
        string $fromName,
        string $subject,
        string $plainBody,
        string $htmlBody
    ): bool {
        $boundary = '=_WPU_' . md5((string) microtime(true));
        $headers = [
            'MIME-Version: 1.0',
            'From: ' . $fromName . ' <' . $fromEmail . '>',
            'Reply-To: ' . $fromEmail,
            'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        ];

        $message = "--{$boundary}\r\n"
            . "Content-Type: text/plain; charset=UTF-8\r\n"
            . "Content-Transfer-Encoding: 8bit\r\n\r\n"
            . $plainBody . "\r\n"
            . "--{$boundary}\r\n"
            . "Content-Type: text/html; charset=UTF-8\r\n"
            . "Content-Transfer-Encoding: 8bit\r\n\r\n"
            . $htmlBody . "\r\n"
            . "--{$boundary}--";

        return mail($toEmail, $subject, $message, implode("\r\n", $headers));
    }
}
