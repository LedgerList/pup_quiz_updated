<?php

namespace App\Http\Controllers;

use App\Models\LoginLogs;
use Illuminate\Http\Request;

class LoginLogsController extends Controller
{
    public function isFirstLogin(Request $request)
    {
        $user = LoginLogs::where('email', $request->input('email'))->first();


        if ($user) {
            return response()->json([
                "exist" => true
            ]);
        } else {
            return response()->json([
                "exist" => false
            ]);
        }
    }
}
