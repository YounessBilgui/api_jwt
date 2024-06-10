<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Validation\ValidationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except'=> ['login','register']]);
    }

    public function register(Request $request)
    {

        $request->validate([
            'name' => 'required|',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        try {
            
            $user = User::create([
            
                'name' => $request->input('name'),
                'email' => $request->input('email'),
                'password' => Hash::make($request->input('password'))
            ]);

                if ($user) {
                    return response()->json([
                        'message' => 'User registered successfully!',
                        'user' => $user
                    ], 201);
        }
                else{
                    return response()->json([
                        'message' => 'User registration failed. Please try again.'
                    ], 400);
        }
            }
        catch (\Exception $e) {
            // Handle any exceptions that may occur
            return response()->json([
                'message' => 'An error occurred during registration: ' . $e->getMessage()
            ], 500);
        
            }


    }

    public function login(Request $request){
        
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:8|',
        ]);
        
        $user = User::where('email', $request->email)->first();

        if(!$user || !hash::check($request->password, $user->password)){
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        // generate the JWT token
        $token = JWTAuth::fromUser($user);

        // store jwt token in cookies 

        $cookies = cookie('auth_token',$token, 60 * 3);


        return response([
            'message'=>'login successful',
            'token' => $token
        ])->withCookie($cookies);
    }
    

    public function logout(Request $request)
    {
        try {
            // Invalidate the token
            JWTAuth::invalidate(JWTAuth::getToken());

            // Optionally, you can also clear the auth_token cookie
            $cookie = cookie('auth_token', '', -1); // Setting the cookie expiration to a past time to delete it

            return response()->json(['message' => 'Successfully logged out'])->withCookie($cookie);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Failed to logout, please try again'], 500);
        }
    }

}
