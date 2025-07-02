package com.example.AuthenticationBackedJava.Authentication.scheduler;

import com.example.AuthenticationBackedJava.Authentication.service.mail.EmailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;


@Component
@Slf4j
public class ScheduledEmailTask {

    @Autowired
    private EmailService emailService;

    @Scheduled(cron = "0 55 11 * * ?") // Every day at 11:55 AM
    public void sendDailyEmail() {
        String to = "ridoy.hossain@bracits.com"; // Hard-code for testing

        if (to != null && !to.isEmpty()) {
            emailService.sendEmail(to, "Test Subject", "Test Body");
        } else {

        }
    }
}
