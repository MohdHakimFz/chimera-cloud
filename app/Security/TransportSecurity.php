<?php
declare(strict_types=1);
namespace App\Security;

final class TransportSecurity
{
    public static function isHttps(array $server): bool
    {
        $https=strtolower(trim((string)($server['HTTPS']??'')));
        if(in_array($https,['on','1','true'],true))return true;
        return strtolower(trim((string)($server['REQUEST_SCHEME']??'')))==='https';
    }

    public static function productionRedirect(array $server,string $path): ?string
    {
        if(strtolower((string)env('APP_ENV','production'))!=='production'||!env_bool('HTTPS_ENFORCE',false)||self::isHttps($server))return null;
        $base=rtrim((string)env('APP_URL',''),'/');
        if(!str_starts_with(strtolower($base),'https://'))return null;
        $query=trim((string)($server['QUERY_STRING']??''));
        return $base.'/'.ltrim($path,'/').($query===''?'':'?'.$query);
    }
}
