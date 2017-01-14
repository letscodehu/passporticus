<?php


Route::get('/', function () {
})->middleware("guest", "auth:web");

Route::get("/home", function(\Illuminate\Contracts\Auth\Guard $auth) {
    return $auth->user();
})->middleware("auth:web");

Route::get('/callback', function (\Illuminate\Http\Request $request) {

    \Auth::login($request->input("code"));

    return redirect("/home");
})->middleware("guest");
