<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\Models\User;

use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class OrganizerRegistrationController extends Controller
{


    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'fullName' => 'required|string|max:255',
            'department' => 'required|string|max:255',
            'username' => 'required|string|max:255|unique:users,username',
            'email' => 'required|email|max:255|unique:users,email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors(),
            ], 422);
        }

        try {
            $user = User::create([
                'name' => $request->input('fullName'),
                'department' => $request->input('department'),
                'username' => $request->input('username'),
                'email' => $request->input('email'),
                'password' => Hash::make($request->input('password')),
                'role' => 3, // 3 = organizer
            ]);

            return response()->json([
                'message' => 'Organizer registered successfully',
                'user' => $user,
            ], 201);
        } catch (\Illuminate\Database\QueryException $e) {
            // Handle database unique constraint violations
            if ($e->getCode() == 23000) { // Integrity constraint violation
                $errorCode = $e->errorInfo[1] ?? null;
                
                // Check if it's a unique constraint violation
                if ($errorCode == 1062) { // MySQL duplicate entry
                    $message = $e->getMessage();
                    
                    // Check which field caused the violation
                    if (strpos($message, 'username') !== false) {
                        return response()->json([
                            'errors' => [
                                'username' => ['The username has already been taken.']
                            ],
                        ], 422);
                    } elseif (strpos($message, 'email') !== false) {
                        return response()->json([
                            'errors' => [
                                'email' => ['The email has already been taken.']
                            ],
                        ], 422);
                    }
                }
            }
            
            // Generic error for other database issues
            return response()->json([
                'message' => 'Registration failed. Please try again.',
                'error' => config('app.debug') ? $e->getMessage() : 'An error occurred during registration.'
            ], 500);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Registration failed. Please try again.',
                'error' => config('app.debug') ? $e->getMessage() : 'An error occurred during registration.'
            ], 500);
        }
    }
}
