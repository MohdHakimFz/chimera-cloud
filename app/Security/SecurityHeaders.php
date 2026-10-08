<?php

declare(strict_types=1);

namespace App\Security;

final class SecurityHeaders
{
    public static function send(): void
    {
        if (headers_sent()) {
            return;
        }

        $policy=self::policy($_SERVER);
        header('Content-Security-Policy: '.$policy['Content-Security-Policy']);
        unset($policy['Content-Security-Policy']);
        foreach($policy as$name=>$value)header($name.': '.$value);
    }

    public static function policy(array $server): array
    {
        $headers=['X-Content-Type-Options'=>'nosniff','X-Frame-Options'=>'DENY','Referrer-Policy'=>'strict-origin-when-cross-origin','Permissions-Policy'=>'camera=(), microphone=(), geolocation=()','Content-Security-Policy'=>"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",'Cache-Control'=>'no-store, private, max-age=0','Pragma'=>'no-cache'];
        if(strtolower((string)env('APP_ENV','production'))==='production'&&TransportSecurity::isHttps($server))$headers['Strict-Transport-Security']='max-age=31536000';
        return$headers;
    }
}
