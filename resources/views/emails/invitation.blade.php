<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ $subject_line }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #fff5f0 0%, #ffe8d6 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .email-container {
            max-width: 600px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(255, 140, 0, 0.15);
            overflow: hidden;
            position: relative;
        }

        .header {
            background: linear-gradient(135deg, #ff8c00 0%, #ff6b35 50%, #f55a00 100%);
            padding: 40px 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255, 255, 255, 0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }

        @keyframes pulse {

            0%,
            100% {
                transform: scale(1) rotate(0deg);
                opacity: 0.5;
            }

            50% {
                transform: scale(1.1) rotate(180deg);
                opacity: 0.8;
            }
        }

        .logo-section {
            position: relative;
            z-index: 2;
        }

        .company-logo {
            width: 80px;
            height: 80px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 3px solid rgba(255, 255, 255, 0.3);
            backdrop-filter: blur(10px);
        }

        .company-logo::before {
            content: url('/images/LOGO.png');
            font-size: 32px;
            color: white;
        }

        .header h1 {
            color: white;
            font-size: 28px;
            font-weight: 300;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            position: relative;
            z-index: 2;
        }

        .header-subtitle {
            color: rgba(255, 255, 255, 0.9);
            font-size: 16px;
            font-weight: 300;
            position: relative;
            z-index: 2;
        }

        .content {
            padding: 50px 40px;
            background: #ffffff;
            position: relative;
        }

        .greeting {
            font-size: 24px;
            color: #2c3e50;
            margin-bottom: 30px;
            font-weight: 400;
            border-left: 4px solid #ff8c00;
            padding-left: 20px;
        }

        .message-body {
            font-size: 16px;
            color: #555;
            margin-bottom: 40px;
            line-height: 1.8;
            text-align: justify;
        }

        .school-logo-container {
            width: 100%;
            margin-top: 20px;
        }

        .school-logo-container img {
            width: 100%;
            height: 100%;
            border-radius: 8px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
            object-fit: contain;
        }

        .divider {
            height: 2px;
            background: linear-gradient(90deg, #ff8c00, #ff6b35, #ff8c00);
            margin: 30px 0;
            border-radius: 1px;
            opacity: 0.3;
        }

        .email-info {
            background: linear-gradient(135deg, #fff8f3 0%, #ffefe6 100%);
            padding: 25px;
            border-radius: 8px;
            border-left: 4px solid #ff8c00;
            margin-top: 30px;
        }

        .email-info p {
            color: #666;
            font-size: 14px;
            margin: 0;
            display: flex;
            align-items: center;
        }

        .email-info p::before {
            content: '📧';
            margin-right: 10px;
            font-size: 16px;
        }

        .footer {
            background: #2c3e50;
            color: #bdc3c7;
            padding: 30px;
            text-align: center;
            font-size: 14px;
        }

        .footer p {
            margin-bottom: 10px;
        }

        .social-links {
            margin-top: 20px;
        }

        .social-links a {
            color: #ff8c00;
            text-decoration: none;
            margin: 0 10px;
            font-size: 18px;
            transition: color 0.3s ease;
        }

        .social-links a:hover {
            color: #ff6b35;
        }

        /* Responsive Design */
        @media only screen and (max-width: 600px) {
            .email-container {
                margin: 10px;
                border-radius: 8px;
            }

            .header {
                padding: 30px 20px;
            }

            .header h1 {
                font-size: 24px;
            }

            .content {
                padding: 30px 25px;
            }

            .greeting {
                font-size: 20px;
            }

            .message-body {
                font-size: 15px;
            }
        }

        /* Print Styles */
        @media print {
            body {
                background: white;
            }

            .email-container {
                box-shadow: none;
                border: 1px solid #ddd;
            }

            .header::before {
                display: none;
            }
        }
    </style>
</head>

<body>
    <div class="email-container">
        <div class="header">
            <div class="logo-section">
                <div class="company-logo">

                    <img src="{{ asset('images/LOGO.png') }}" alt="App Logo" style="width: 100%; height:100%;">
                </div>
                <h1>{{ $subject_line }}</h1>
                <div class="header-subtitle">PUPT QUIZ</div>
            </div>
        </div>

        <div class="content">
            <h2 class="greeting">Hello {{ $name }},</h2>
            @if ($link !== '#')
            <div class="message-body">
                <p>You are invited to our quiz event! 🎉</p>
                <p>Please click the button below to participate:</p>

            </div>
            @endif
            @if ($link === '#')
            <p style="color:#e53935;font-weight:bold;">Your registration has been rejected.</p>
            @else
            <p>
                <a href="{{ $link }}"
                    style="display:inline-block;padding:10px 20px;
                   background:#4CAF50;color:#fff;
                   text-decoration:none;border-radius:5px;">
                    Join Quiz
                </a>
            </p>
            @endif
            <div class="divider"></div>

            <div class="email-info">
                <p>We sent this email to: {{ $email }}</p>
            </div>

        </div>

        <div class="footer">
            <p>&copy; 2025 PuptQuiz. All rights reserved.</p>
            <p>This email was sent from an automated system, please do not reply directly.</p>
            <div class="social-links">
                <a href="https://puptquiz.com/">🌐</a>

            </div>
        </div>
    </div>
</body>

</html>