<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Arr;
use app\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function login(Request $request) {
        $validate = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required',
        ]);

        if ($validate->fails()) {
            $response = [
                'status' => 'error',
                'message' => 'validator error',
                'errors' => $validate->errors(),
                'content' => null,
            ];
            return response()->json($response, 401);
        } else {
            $credentials = request(['email', 'password']);
            $credentials = Arr::add($credentials, 'status', 'active');
            if (!Auth::attempt($credentials)) {
                $response = [
                    'status' => 'error',
                    'message' => 'Unauthorized',
                    'errors' => null,
                    'content' => null,
                ];
                return response()->json($response, 401);
            }
            $user = User::where('email', $request->email)->first();
            if (! Hash::check($request->password, $user->password, [])) {
                throw new \Exception;
            }
            $tokenResult = $user->createToken('token-auth')->plainTextToken;
            $response = [
                'status' => 'success',
                'message' => 'Login successfully',
                'errors' => null,
                'content' => [
                    'status_code'=> 200,
                    'access_token' => $tokenResult,
                    'token_type' => 'Bearer',
                ],
            ];
            return response()->json($response, 200);
        }
    }

    public function logout(Request $request) {
        $user = $request->user();
        $user->currentAccessToken()->delete();
        $response = [
            'status' => 'success',
            'message' => 'Logout successfully',
            'errors' => null,
            'content' => null,
        ];
        return response()->json($response, 200);
    }

    public function logoutall(Request $request) {
        $user = $request->user();
        $user->tokens()->delete();
        $response = [
            'status' => 'success',
            'message' => 'Logout successfully',
            'errors' => null,
            'content' => null,
        ];
        return response()->json($response, 200);
    }
}