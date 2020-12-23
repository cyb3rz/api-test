<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use App\Models\User;
use App\Notifications\SignupActivate;
use Str;

class AuthController extends Controller
{
    /**
     * Create user
     *
     * @param  [string] name
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @return [string] message
     */
    public function signup(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);
        // $user = new User([
        //     'name' => $request->name,
        //     'email' => $request->email,
        //     'password' => bcrypt($request->password),
        //     'activation_code' => Str::random(4)
        // ]);
        // $user->save();

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'activation_code' => Str::random(4)
        ]);

        $token = $user->createToken('authToken')->accessToken;

        $user->notify(new SignupActivate($user));

        return response()->json([
            'message' => 'Successfully created user!',
            'user' => $user,
            'token' => $token
        ], 200);
    }

    /**
     * Login user and create token
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [boolean] remember_me
     * @return [string] access_token
     * @return [string] token_type
     * @return [string] expires_at
     */
    public function login(Request $request)
    {
        $loginData = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);
        $credentials = request(['email', 'password']);

        $credentials['verified'] = 1;
        $credentials['deleted_at'] = null;


        if (!auth()->attempt($loginData)) {
            return response(['message' => 'This User does not exist, check your details'], 400);
        }

        if (!auth::user()->verified) {
            return response(['message' => 'Email not verified!'], 400);
        }

        $accessToken = auth()->user()->createToken('authToken')->accessToken;


        // if ($request->remember_me)
        //     $accessToken->expires_at = Carbon::now()->addWeeks(1);
        // $token->save();

        return response()->json([
            'access_token' => $accessToken,
            //'token_type' => 'Bearer',
            //'expires_at' => Carbon::parse($accessToken->expires_at)->toDateTimeString()
        ]);
    }


    public function signupActivate($code)
    {
        $user = User::where('activation_code', $code)->first();
        if (!$user) {

            return response()->json(['message' => 'This activation token is invalid.'], 404);
        }

        $user->verified = true;
        $user->activation_code = '';
        $user->save();

        return $user;
    }

    /**
     * Logout user (Revoke the token)
     *
     * @return [string] message
     */
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }

    /**
     * Get the authenticated User
     *
     * @return [json] user object
     */
    public function user(Request $request)
    {
        return response()->json($request->user());
    }
}
