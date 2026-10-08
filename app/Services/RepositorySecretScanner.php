<?php
declare(strict_types=1);
namespace App\Services;

use RecursiveDirectoryIterator;use RecursiveIteratorIterator;use SplFileInfo;

final class RepositorySecretScanner
{
    public static function scan(string $root): array
    {
        $findings=[];$iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,RecursiveDirectoryIterator::SKIP_DOTS));
        foreach($iterator as$file){if(!$file instanceof SplFileInfo||!$file->isFile())continue;$path=str_replace('\\','/',$file->getPathname());$relative=ltrim(substr($path,strlen(str_replace('\\','/',$root))),'/');if(self::excluded($relative))continue;if(!preg_match('/\.(php|js|html|md|json|example|htaccess)$/i',$relative)&&!in_array(basename($relative),['.gitignore','.htaccess'],true))continue;$content=file_get_contents($file->getPathname());if(!is_string($content))continue;
            foreach(['PRIVATE_KEY'=>'/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/','AWS_ACCESS_KEY'=>'/\bAKIA[0-9A-Z]{16}\b/','HARDCODED_DB_DSN_PASSWORD'=>'/mysql:[^\r\n]{0,200}(?:password|pwd)=[^\s;"\']+/i']as$category=>$pattern)if(preg_match($pattern,$content)===1)$findings[]=['file'=>$relative,'category'=>$category,'status'=>'FAIL'];
            if(preg_match('/^\s*DB_PASSWORD\s*=\s*(?!<|replace_|change_|$)[^\s#]{8,}/im',$content)===1)$findings[]=['file'=>$relative,'category'=>'HARDCODED_DB_PASSWORD','status'=>'FAIL'];
        }
        return$findings;
    }
    private static function excluded(string$path):bool{return$path==='.env'||str_starts_with($path,'storage/')||str_starts_with($path,'.git/')||str_starts_with($path,'vendor/');}
}
