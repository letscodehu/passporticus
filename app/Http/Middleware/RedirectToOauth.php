<?php
/**
 * Created by PhpStorm.
 * User: tacsiazuma
 * Date: 2017.01.14.
 * Time: 16:30
 */

namespace App\Http\Middleware;


class RedirectToOauth {

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        if (!Auth::check()) {
            return redirect('/home');
        }

        return $next($request);
    }

}