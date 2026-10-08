<?php

declare(strict_types=1);

namespace App\Services;

final class EvidenceExportService
{
    public const TYPES = ['security_events','security_sessions','score_contributors','deception_interactions','adaptive_timeline','lab_evaluation','session_evidence'];

    public static function generate(string $type, string $format, array $filters, ?int $sessionId = null): ?array
    {
        if (!in_array($type, self::TYPES, true) || !in_array($format, ['json','csv'], true)) return null;
        $rows = SecurityAnalyticsService::exportRows($type, $filters, $sessionId);
        if ($rows === null) return null;
        if ($format === 'json') return ['content_type'=>'application/json; charset=utf-8','extension'=>'json','body'=>json_encode(['export_type'=>$type,'generated_at'=>gmdate('c'),'data'=>$rows],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR)];
        return ['content_type'=>'text/csv; charset=utf-8','extension'=>'csv','body'=>self::csv($rows)];
    }

    public static function neutralizeCsvCell(mixed $value): string
    {
        if (is_bool($value)) return $value ? 'true' : 'false';
        if ($value === null) return '';
        if (is_array($value) || is_object($value)) $value=json_encode($value,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
        $value=(string)$value;
        return preg_match('/\A\s*[=+\-@]/u',$value)===1?"'".$value:$value;
    }

    private static function csv(array $rows): string
    {
        $flat=array_map([self::class,'flatten'],$rows);$headers=[];foreach($flat as $row)$headers=array_values(array_unique([...$headers,...array_keys($row)]));
        $stream=fopen('php://temp','w+');if($stream===false)return'';fputcsv($stream,$headers);
        foreach($flat as $row){$line=[];foreach($headers as $header)$line[]=self::neutralizeCsvCell($row[$header]??'');fputcsv($stream,$line);}rewind($stream);$csv=stream_get_contents($stream);fclose($stream);return is_string($csv)?$csv:'';
    }

    private static function flatten(array $row): array
    {
        $flat=[];foreach($row as $key=>$value)$flat[$key]=(is_array($value)||is_object($value))?json_encode($value,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR):$value;return$flat;
    }
}
