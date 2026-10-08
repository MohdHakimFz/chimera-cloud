<?php
declare(strict_types=1);
namespace App\Models;
use App\Core\Database;
use App\Services\SecuritySessionService;
use PDO;

final class SecuritySession
{
    public static function all(int $limit=100): array
    {
        $statement=Database::connection()->prepare('SELECT s.id,s.user_id,s.source_hash,s.threat_score,s.classification,s.request_count,s.first_seen_at,s.last_seen_at,CASE WHEN s.last_seen_at >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL '.SecuritySessionService::WINDOW_MINUTES.' MINUTE) THEN \'ACTIVE\' ELSE \'EXPIRED\' END AS lifecycle_status,u.name AS actor_name,(SELECT COUNT(*) FROM security_score_contributors c WHERE c.security_session_id=s.id) AS contributor_count FROM security_sessions s LEFT JOIN users u ON u.id=s.user_id ORDER BY s.last_seen_at DESC,s.id DESC LIMIT :limit');
        $statement->bindValue('limit',min(max($limit,1),100),PDO::PARAM_INT);$statement->execute();return array_map([self::class,'present'],$statement->fetchAll());
    }
    public static function find(int $id): ?array
    {
        $statement=Database::connection()->prepare('SELECT s.id,s.user_id,s.source_hash,s.threat_score,s.classification,s.request_count,s.first_seen_at,s.last_seen_at,CASE WHEN s.last_seen_at >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL '.SecuritySessionService::WINDOW_MINUTES.' MINUTE) THEN \'ACTIVE\' ELSE \'EXPIRED\' END AS lifecycle_status,u.name AS actor_name FROM security_sessions s LEFT JOIN users u ON u.id=s.user_id WHERE s.id=:id LIMIT 1');$statement->execute(['id'=>$id]);$session=$statement->fetch();if(!is_array($session))return null;
        $contributors=Database::connection()->prepare('SELECT id,rule_code,label,risk_delta,created_at FROM security_score_contributors WHERE security_session_id=:id ORDER BY created_at,id');$contributors->execute(['id'=>$id]);
        $events=Database::connection()->prepare('SELECT id,event_type,severity,risk_delta,endpoint,http_method,created_at FROM security_events WHERE security_session_id=:id ORDER BY created_at,id');$events->execute(['id'=>$id]);
        $session=self::present($session);$session['contributors']=$contributors->fetchAll();$session['events']=$events->fetchAll();$session['contributor_total']=array_sum(array_map(static fn(array $row):int=>(int)$row['risk_delta'],$session['contributors']));return $session;
    }
    public static function summary(): array
    {
        $database=Database::connection();$rows=$database->query('SELECT classification,COUNT(*) total FROM security_sessions GROUP BY classification')->fetchAll();$by=['LOW'=>0,'MEDIUM'=>0,'HIGH'=>0,'CRITICAL'=>0];foreach($rows as $row)$by[$row['classification']]=(int)$row['total'];return ['total'=>array_sum($by),'active'=>(int)$database->query('SELECT COUNT(*) FROM security_sessions WHERE last_seen_at >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL '.SecuritySessionService::WINDOW_MINUTES.' MINUTE)')->fetchColumn(),'by_classification'=>$by];
    }
    private static function present(array $row): array { foreach(['id','user_id','threat_score','request_count','contributor_count'] as $key)if(isset($row[$key]))$row[$key]=(int)$row[$key];return $row; }
}
