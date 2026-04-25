CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL UNIQUE,
  `password` varchar(255) NOT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `token` varchar(64) NOT NULL UNIQUE,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `expires_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `attacks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `source_type` varchar(50) DEFAULT NULL,
  `attack_type` varchar(100) DEFAULT NULL,
  `attack_name` varchar(150) DEFAULT NULL,
  `threat_score` decimal(5,2) DEFAULT NULL,
  `threat_level` varchar(50) DEFAULT NULL,
  `source_ip` varchar(45) DEFAULT NULL,
  `username` varchar(100) DEFAULT NULL,
  `event_time` varchar(100) DEFAULT NULL,
  `recommended_actions` text,
  `raw_context` text,
  `status` varchar(50) DEFAULT 'active',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX (`threat_level`),
  INDEX (`status`),
  INDEX (`source_ip`),
  INDEX (`attack_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `attack_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attack_id` int(11) NOT NULL,
  `log_text` text NOT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`attack_id`) REFERENCES `attacks`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `attack_timelines` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attack_id` int(11) NOT NULL,
  `timestamp` varchar(100) DEFAULT NULL,
  `description` text NOT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`attack_id`) REFERENCES `attacks`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
