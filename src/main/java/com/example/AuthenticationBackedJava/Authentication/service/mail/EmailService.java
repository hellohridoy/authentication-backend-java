package com.example.AuthenticationBackedJava.Authentication.service.mail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    @Autowired
    private JavaMailSender mailSender;

    public void sendEmail(String to, String subject, String body) {
        try {
            // Validate email addresses
            if (to == null || to.trim().isEmpty() || !isValidEmail(to)) {
                logger.error("Invalid recipient email address: {}", to);
                return;
            }

            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("ridoy.java@gmail.com"); // Use your actual email
            message.setTo(to.trim());
            message.setSubject(subject);
            message.setText(body);

            mailSender.send(message);
            logger.info("Email sent successfully to: {}", to);
        } catch (MailException e) {
            logger.error("Mail sending failed: {}", e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Could not parse mail: {}", e.getMessage(), e);
        }
    }

    private boolean isValidEmail(String email) {
        return email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }
}
