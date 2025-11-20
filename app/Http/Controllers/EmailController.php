<?php

namespace App\Http\Controllers;

use App\Mail\OtpMail;
use App\Models\LoginLogs;
use App\Models\LoginOtp;
use App\Models\User;
use Exception;
use Illuminate\Auth\Events\Login;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use PDO;

class EmailController extends Controller
{
    //

    public function verifyOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'otp' => 'required|digits:6',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json(['error' => 'User not found'], 404);
        }

        $otpLogin = LoginOtp::where("email", $request->email)->first();
        
        if (!$otpLogin) {
            return response()->json(['error' => 'OTP not found. Please request a new one.'], 404);
        }
        
        // Check expiration
        if (now()->greaterThan($otpLogin->otp_expires_at)) {
            return response()->json(['error' => 'OTP expired'], 400);
        }

        // Check code
        if ($request->otp !== $otpLogin->otp) {
            return response()->json(['error' => 'Invalid OTP'], 400);
        }

        // Delete the OTP after successful verification
        $lOtp = LoginOtp::where('email', $request->email)->firstOrFail();
        $lOtp->delete();

        // Create LoginLogs entry to mark that user has completed first login verification
        $login_log = LoginLogs::where("email", $request->email)->first();
        if (!$login_log) {
            LoginLogs::create([
                "user_id" => $user->id,
                "email" => $request->email,
            ]);
        }

        // Log the user in after successful OTP verification
        Auth::login($user);
        $request->session()->regenerate();
        session(['role' => $user->role]);

        return response()->json([
            'success' => 'OTP verified successfully. Redirecting to dashboard...'
        ], 200);
    }

    public function resendOTP(Request $request)
    {
        $user = User::where("email", $request->email)->first();
        $lOtp = LoginOtp::where('email', $request->email)->firstOrFail();


        if (!$user) {
            return response()->json([
                "error" => "Email not found"
            ], 404);
        }
        if ($lOtp) {
            $lOtp->delete();
        }

        try {
            $otp = rand(100000, 999999);



            LoginOtp::create([
                "otp" =>  $otp,
                "code" => "",
                "email" => $request->email,
                "otp_expires_at" =>  now()->addMinutes(5)
            ]);

            $name = $user->name;
            $email = $request->email;
            $subject = "Your OTP Code";
            $body = "Your OTP code is "  . $otp . ". It expires in 5 minutes.";

            Mail::to($email)->send(new OtpMail($name, $email, $subject, $body));

            return response()->json(['success' => 'New OTP sent successfully'], 200);
        } catch (Exception $e) {
            return response()->json([
                "msg" => "Failed to send OTP email",
                "error" => $e->getMessage()  // will show the actual error message
            ], 500);
        }
    }

    public function sendOtp(Request $request)
    {


        $lOtp = LoginOtp::where('email', $request->email)->first();
        $user = User::where("email", $request->email)->first();

        if (!$user) {
            return back()->withErrors([
                'email' => 'Email not found',
            ]);
        }
        if ($lOtp) {
            $lOtp->delete();
        }


        if (!Hash::check($request->password, $user->password)) {
            return back()->withErrors([
                'password' => 'Invalid password',
            ]);
        }
        try {
            $otp = rand(100000, 999999);
            $login_log = LoginLogs::where("email", $request->email)->first();

            if (!$login_log) {
                LoginLogs::create([
                    "user_id" => $user->id,
                    "email" => $request->email,
                ]);
            }

            LoginOtp::create([
                "otp" =>  $otp,
                "code" => "",
                "email" => $request->email,
                "otp_expires_at" =>  now()->addMinutes(5)
            ]);

            $name = $user->name;
            $email = $request->email;
            $subject = "Your OTP Code";
            $body = "Your OTP code is "  . $otp . ". It expires in 5 minutes.";

            Mail::to($email)->send(new OtpMail($name, $email, $subject, $body));

            return back()->with('success', 'OTP sent successfully! Please check your email.');
        } catch (Exception $e) {
            return back()->withErrors([
                'email' => 'Failed to send OTP email: ' . $e->getMessage()
            ]);
        }

        // // Success
        // return response()->json([
        //     "msg" => "Login successful",
        //     "user" => $user
        // ]);

        // return "OTP Email Sent!";
    }

    public function sendRegistrationOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
        ]);

        $user = User::where("email", $request->email)->first();

        if (!$user) {
            return response()->json([
                "error" => "User not found"
            ], 404);
        }

        // Delete any existing OTP for this email
        $lOtp = LoginOtp::where('email', $request->email)->first();
        if ($lOtp) {
            $lOtp->delete();
        }

        try {
            $otp = rand(100000, 999999);

            LoginOtp::create([
                "otp" => $otp,
                "code" => "",
                "email" => $request->email,
                "otp_expires_at" => now()->addMinutes(5)
            ]);

            $name = $user->name;
            $email = $request->email;
            $subject = "Email Verification - Your OTP Code";
            $body = "Thank you for registering! Your OTP code is " . $otp . ". It expires in 5 minutes.";

            Mail::to($email)->send(new OtpMail($name, $email, $subject, $body));

            return response()->json(['success' => 'OTP sent successfully'], 200);
        } catch (Exception $e) {
            return response()->json([
                "error" => "Failed to send OTP email: " . $e->getMessage()
            ], 500);
        }
    }
}
