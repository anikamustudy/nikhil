<!DOCTYPE html>
<html>

<head>
  <meta charset="UTF-8">
  <title>{{ $title }}</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
      margin: 0;
      padding: 0;
    }

    .container {
      max-width: 600px;
      margin: 20px auto;
      background: #ffffff;
      border-radius: 8px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    }

    .header {
      background: #4a90e2;
      color: #ffffff;
      padding: 20px;
      text-align: center;
      border-top-left-radius: 8px;
      border-top-right-radius: 8px;
    }

    .content {
      padding: 20px;
      color: #333333;
    }

    .details {
      margin-top: 20px;
    }

    .details p {
      margin: 5px 0;
    }

    .button {
      display: inline-block;
      padding: 12px 24px;
      background: #4a90e2;
      color: #ffffff;
      text-decoration: none;
      border-radius: 5px;
      margin-top: 20px;
    }

    .footer {
      text-align: center;
      padding: 20px;
      font-size: 12px;
      color: #777777;
    }
  </style>
</head>

<body>
  <div class="container">
    <div class="header">
      <h1>{{ $title }}</h1>
    </div>
    <div class="content">
      <p>{{ $intro }}</p>

      @if ($tempPassword)
      <p><strong>Temporary Password:</strong> {{ $tempPassword }}</p>
    @endif

      @if ($details)
      <div class="details">
      <h3>Your Details</h3>
      @foreach ($details as $key => $value)
      <p><strong>{{ $key }}:</strong> {{ $value }}</p>
    @endforeach
      </div>
    @endif

      @if ($resetUrl)
      <a href="{{ $resetUrl }}" class="button">Reset Your Password</a>
    @endif
    </div>
    <div class="footer">
      <p>© {{ date('Y') }} {{ config('app.name') }}. All rights reserved.</p>
    </div>
  </div>
</body>

</html>