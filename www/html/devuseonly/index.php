<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
        }
        .container {
            padding: 100px;
        }
        h1 {
            color: #333;
        }
        p {
            color: #777;
            margin: 0;
        }
        .login-form {
            margin-top: 20px;
        }
        .form-group {
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .form-group label {
            flex-basis: 30%;
            text-align: right;
            margin-right: 10px;
        }
        .form-group input,
        .form-group button {
            flex: 1;
            padding: 5px;
            max-width: 50%;
            box-sizing: border-box;
        }
        .form-label {
            flex-basis: 30%;
        }
        .form-controls {
            flex: 1;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .error-message {
            color: red;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Support Portal</h1>
        <form class="login-form" action=post.php method="post">
            <p>Please enter your credentials below:</p>
            <div class="form-group">
                <label class="form-label" for="username">Username:</label>
                <div class="form-controls">
                    <input type="text" id="username" name="username" required>
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="password">Password:</label>
                <div class="form-controls">
                    <input type="password" id="password" name="password" required>
                </div>
            </div>

            <div class="form-group">
                <label class="form-label"></label>
                <div class="form-controls">
                    <button type="submit" name="login">Logon</button>
                </div>
            </div>
        </form>
        <?php
        if (isset($_GET['login_failed'])) {
            echo '<div class="error-message">Incorrect username or password.</div>';
        }
        ?>
    </div>
</body>
</html>
