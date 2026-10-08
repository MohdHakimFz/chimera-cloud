<?php

declare(strict_types=1);

namespace App\Services;

use App\Core\Database;
use App\Security\SecurityEventTaxonomy;
use DateTimeImmutable;
use PDO;
use Throwable;

final class SecurityAnalyticsService
{
    public const MAX_TIMELINE = 200;
    public const MAX_EXPORT = 1000;
    private const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    private const PROFILES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    private const LAB_TYPES = ['LAB_MODULE_ACCESSED', 'LAB_VULNERABILITY_INTERACTION', 'LAB_REMEDIATED_TEST', 'LAB_MODULE_STATE_CHANGED'];
    private const ADAPTIVE_TYPES = ['DECEPTION_PROFILE_SELECTED', 'DECEPTION_PROFILE_CHANGED', 'ADAPTIVE_DECOY_RENDERED'];
    private const FILTER_KEYS = ['date_from', 'date_to', 'category', 'type', 'severity', 'threat_level', 'profile', 'module'];

    public static function filters(array $input): array
    {
        $filters = ['date_from' => '', 'date_to' => '', 'category' => '', 'type' => '', 'severity' => '', 'threat_level' => '', 'profile' => '', 'module' => '', 'errors' => [], 'valid' => true];
        $allow = [
            'category' => SecurityEventTaxonomy::categories(),
            'type' => SecurityEventTaxonomy::eventTypes(),
            'severity' => SecurityEventTaxonomy::severities(),
            'threat_level' => self::LEVELS,
            'profile' => self::PROFILES,
            'module' => ['CHIM-VULN-001', 'CHIM-VULN-002', 'CHIM-VULN-003'],
        ];
        foreach ($allow as $key => $values) {
            $value = is_scalar($input[$key] ?? null) ? trim((string) $input[$key]) : '';
            if ($value !== '' && !in_array($value, $values, true)) {
                $filters['errors'][] = "Unsupported {$key} filter.";
            } else {
                $filters[$key] = $value;
            }
        }
        foreach (['date_from', 'date_to'] as $key) {
            $value = is_scalar($input[$key] ?? null) ? trim((string) $input[$key]) : '';
            if ($value !== '' && !self::validDate($value)) {
                $filters['errors'][] = "Invalid {$key} date.";
            } else {
                $filters[$key] = $value;
            }
        }
        if (($filters['date_from'] === '') !== ($filters['date_to'] === '')) {
            $filters['errors'][] = 'Both date_from and date_to are required for a bounded date range.';
            $filters['date_from'] = $filters['date_to'] = '';
        } elseif ($filters['date_from'] !== '' && $filters['date_to'] !== '') {
            $from = new DateTimeImmutable($filters['date_from']);
            $to = new DateTimeImmutable($filters['date_to']);
            if ($from > $to || $from->diff($to)->days > 366) {
                $filters['errors'][] = 'Date range must be chronological and no longer than 366 days.';
                $filters['date_from'] = $filters['date_to'] = '';
            }
        }
        $filters['valid'] = $filters['errors'] === [];
        return $filters;
    }

    public static function exportFilterKeys(string $type): array
    {
        return match ($type) {
            'security_events', 'deception_interactions', 'adaptive_timeline', 'lab_evaluation' => self::FILTER_KEYS,
            'security_sessions', 'score_contributors' => ['date_from', 'date_to', 'threat_level'],
            'session_evidence' => [],
            default => [],
        };
    }

    public static function exportFilterErrors(string $type, array $filters): array
    {
        $errors = $filters['errors'] ?? [];
        if (!in_array($type, EvidenceExportService::TYPES, true)) return $errors;
        $allowed = self::exportFilterKeys($type);
        foreach (self::FILTER_KEYS as $key) {
            if (($filters[$key] ?? '') !== '' && !in_array($key, $allowed, true)) {
                $errors[] = "The {$key} filter is not supported for {$type} exports.";
            }
        }
        return array_values(array_unique($errors));
    }

    public static function dashboard(array $filters = []): array
    {
        $filters = isset($filters['errors']) ? $filters : self::filters($filters);
        return [
            'filters' => $filters,
            'events' => self::eventMetrics($filters),
            'sessions' => self::sessionMetrics($filters),
            'session_list' => self::sessionList($filters, 25),
            'deception' => self::deceptionMetrics($filters),
            'detection' => self::detectionMetrics($filters),
            'lab' => self::labEvaluation($filters),
            'timeline' => self::timeline($filters, 50),
        ];
    }

    public static function eventMetrics(array $filters): array
    {
        [$where, $params] = self::eventWhere($filters);
        $database = Database::connection();
        $total = self::scalar("SELECT COUNT(*) FROM security_events e {$where}", $params);
        $groups = [];
        foreach ([
            'by_category' => "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json, '$.category')), 'UNKNOWN')",
            'by_severity' => 'e.severity',
            'by_type' => 'e.event_type',
        ] as $name => $expression) {
            $statement = $database->prepare("SELECT {$expression} label, COUNT(*) total FROM security_events e {$where} GROUP BY label ORDER BY total DESC, label");
            $statement->execute($params);
            $groups[$name] = array_map(self::groupPresenter(...), $statement->fetchAll());
        }
        $statement = $database->prepare("SELECT DATE(e.created_at) label, COUNT(*) total FROM security_events e {$where} GROUP BY label ORDER BY label");
        $statement->execute($params);
        return ['total' => $total, ...$groups, 'over_time' => array_map(self::groupPresenter(...), $statement->fetchAll()), 'lab_total' => self::countTypes(self::LAB_TYPES, $filters)];
    }

    public static function sessionMetrics(array $filters): array
    {
        [$where, $params] = self::sessionWhere($filters);
        $database = Database::connection();
        $statement = $database->prepare("SELECT s.threat_score,s.classification,s.last_seen_at FROM security_sessions s {$where}");
        $statement->execute($params);
        $rows = $statement->fetchAll();
        $byLevel = array_fill_keys(self::LEVELS, 0);
        $scores = [];
        $active = 0;
        foreach ($rows as $row) {
            $byLevel[$row['classification']]++;
            $scores[] = (int) $row['threat_score'];
            if (strtotime((string) $row['last_seen_at']) >= time() - SecuritySessionService::WINDOW_MINUTES * 60) {
                $active++;
            }
        }
        $contributor = $database->prepare("SELECT c.rule_code label,COUNT(*) total,SUM(c.risk_delta) points FROM security_score_contributors c JOIN security_sessions s ON s.id=c.security_session_id {$where} GROUP BY c.rule_code ORDER BY total DESC,label");
        $contributor->execute($params);
        $contributors = array_map(static fn (array $row): array => ['label' => $row['label'], 'total' => (int) $row['total'], 'points' => (int) $row['points']], $contributor->fetchAll());
        return [
            'total' => count($rows), 'active' => $active, 'expired' => count($rows) - $active, 'by_level' => $byLevel,
            'average_score' => $scores === [] ? null : round(array_sum($scores) / count($scores), 2),
            'minimum_score' => $scores === [] ? null : min($scores), 'maximum_score' => $scores === [] ? null : max($scores),
            'median_score' => EvaluationService::median($scores),
            'reached' => ['MEDIUM' => count(array_filter($scores, static fn (int $v): bool => $v >= 20)), 'HIGH' => count(array_filter($scores, static fn (int $v): bool => $v >= 45)), 'CRITICAL' => count(array_filter($scores, static fn (int $v): bool => $v >= 75))],
            'contributors' => $contributors,
        ];
    }

    public static function sessionList(array $filters, int $limit=25): array
    {
        [$where,$params]=self::sessionWhere($filters);$statement=Database::connection()->prepare("SELECT s.id,s.threat_score,s.classification,s.first_seen_at,s.last_seen_at,CASE WHEN s.last_seen_at>=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL ".SecuritySessionService::WINDOW_MINUTES." MINUTE) THEN 'ACTIVE' ELSE 'EXPIRED' END lifecycle_status,(SELECT COUNT(*) FROM security_score_contributors c WHERE c.security_session_id=s.id) contributor_count FROM security_sessions s {$where} ORDER BY s.last_seen_at DESC,s.id DESC LIMIT :limit");foreach($params as$key=>$value)$statement->bindValue($key,$value);$statement->bindValue('limit',min(max($limit,1),100),PDO::PARAM_INT);$statement->execute();return array_map(static function(array$row):array{return['internal_id'=>(int)$row['id'],'evidence_id'=>EvaluationService::evidenceId('SEC',(int)$row['id']),'threat_score'=>(int)$row['threat_score'],'classification'=>$row['classification'],'lifecycle_status'=>$row['lifecycle_status'],'contributor_count'=>(int)$row['contributor_count'],'first_seen_at'=>$row['first_seen_at'],'last_seen_at'=>$row['last_seen_at']];},$statement->fetchAll());
    }

    public static function deceptionMetrics(array $filters): array
    {
        $database = Database::connection();
        [$where, $params] = self::eventWhere($filters, ['DECOY_ACCESSED', 'HONEYTOKEN_TRIGGERED', ...self::ADAPTIVE_TYPES]);
        $statement = $database->prepare("SELECT e.event_type,JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json,'$.target_identifier')) target_identifier,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json,'$.deception_profile')),JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json,'$.selected_profile')),'UNSPECIFIED') profile,e.security_session_id,e.metadata_json FROM security_events e {$where}");
        $statement->execute($params);
        $rows = $statement->fetchAll();
        $counts = array_fill_keys(['DECOY_ACCESSED', 'HONEYTOKEN_TRIGGERED', ...self::ADAPTIVE_TYPES], 0);
        $byDecoy = $byProfile = $transitions = [];
        $sessions = [];
        foreach ($rows as $row) {
            $type = (string) $row['event_type'];
            $counts[$type]++;
            if ($row['security_session_id'] !== null && in_array($type, ['DECOY_ACCESSED', 'HONEYTOKEN_TRIGGERED'], true)) $sessions[(int) $row['security_session_id']] = true;
            if ($type === 'DECOY_ACCESSED') self::increment($byDecoy, (string) ($row['target_identifier'] ?: 'UNKNOWN'));
            if (in_array($type, ['DECOY_ACCESSED', 'HONEYTOKEN_TRIGGERED', 'ADAPTIVE_DECOY_RENDERED'], true)) self::increment($byProfile, (string) $row['profile']);
            if ($type === 'DECEPTION_PROFILE_CHANGED') {
                $meta = self::metadata($row['metadata_json']);
                self::increment($transitions, ($meta['previous_profile'] ?? 'UNKNOWN') . ' -> ' . ($meta['selected_profile'] ?? 'UNKNOWN'));
            }
        }
        return ['decoy_interactions' => $counts['DECOY_ACCESSED'], 'unique_decoys' => count($byDecoy), 'by_decoy' => self::mapCounts($byDecoy), 'honeytoken_triggers' => $counts['HONEYTOKEN_TRIGGERED'], 'sessions_with_deception' => count($sessions), 'profile_selections' => $counts['DECEPTION_PROFILE_SELECTED'], 'profile_transitions' => $counts['DECEPTION_PROFILE_CHANGED'], 'adaptive_renders' => $counts['ADAPTIVE_DECOY_RENDERED'], 'interactions_by_profile' => self::mapCounts($byProfile), 'transitions' => self::mapCounts($transitions)];
    }

    public static function detectionMetrics(array $filters): array
    {
        [$where, $params] = self::sessionWhere($filters);
        $statement = Database::connection()->prepare("SELECT s.id,(SELECT MIN(created_at) FROM security_events WHERE security_session_id=s.id) first_event,(SELECT MIN(created_at) FROM security_score_contributors WHERE security_session_id=s.id AND risk_delta>0) first_positive,(SELECT MIN(created_at) FROM security_events WHERE security_session_id=s.id AND event_type='DECOY_ACCESSED') first_decoy,(SELECT MIN(created_at) FROM security_events WHERE security_session_id=s.id AND event_type='HONEYTOKEN_TRIGGERED') first_honeytoken FROM security_sessions s {$where}");
        $statement->execute($params);
        $detection = $deception = $honeytoken = [];
        foreach ($statement->fetchAll() as $row) {
            $detection[] = EvaluationService::secondsBetween($row['first_event'], $row['first_positive']);
            $deception[] = EvaluationService::secondsBetween($row['first_positive'], $row['first_decoy']);
            $honeytoken[] = EvaluationService::secondsBetween($row['first_positive'], $row['first_honeytoken']);
        }
        return ['detection_latency' => EvaluationService::durationSummary($detection), 'time_to_deception' => EvaluationService::durationSummary($deception), 'time_to_honeytoken' => EvaluationService::durationSummary($honeytoken)];
    }

    public static function sessionAnalysis(int $id): ?array
    {
        if ($id < 1) return null;
        $database = Database::connection();
        $statement = $database->prepare("SELECT s.id,s.user_id,s.threat_score,s.classification,s.request_count,s.first_seen_at,s.last_seen_at,CASE WHEN s.last_seen_at>=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL " . SecuritySessionService::WINDOW_MINUTES . " MINUTE) THEN 'ACTIVE' ELSE 'EXPIRED' END lifecycle_status,u.name actor_name FROM security_sessions s LEFT JOIN users u ON u.id=s.user_id WHERE s.id=:id LIMIT 1");
        $statement->execute(['id' => $id]);
        $session = $statement->fetch();
        if (!is_array($session)) return null;
        $eventsQuery = $database->prepare('SELECT id,event_type,severity,risk_delta,endpoint,http_method,metadata_json,created_at FROM security_events WHERE security_session_id=:id ORDER BY created_at,id LIMIT 500');
        $eventsQuery->execute(['id' => $id]);
        $events = $eventsQuery->fetchAll();
        $contributorsQuery = $database->prepare('SELECT id,rule_code,label,risk_delta,created_at FROM security_score_contributors WHERE security_session_id=:id ORDER BY created_at,id LIMIT 500');
        $contributorsQuery->execute(['id' => $id]);
        $contributors = $contributorsQuery->fetchAll();
        $contributorAggregate=$database->prepare('SELECT COUNT(*) total,COALESCE(SUM(risk_delta),0) points,MIN(CASE WHEN risk_delta>0 THEN created_at END) first_positive FROM security_score_contributors WHERE security_session_id=:id');$contributorAggregate->execute(['id'=>$id]);$contributorEvidence=$contributorAggregate->fetch();
        $timingQuery=$database->prepare("SELECT MIN(created_at) first_event,MIN(CASE WHEN event_type='DECOY_ACCESSED' THEN created_at END) first_decoy,MIN(CASE WHEN event_type='HONEYTOKEN_TRIGGERED' THEN created_at END) first_honeytoken,SUM(CASE WHEN event_type='HONEYTOKEN_TRIGGERED' THEN 1 ELSE 0 END) honeytoken_count FROM security_events WHERE security_session_id=:id");$timingQuery->execute(['id'=>$id]);$timing=$timingQuery->fetch();
        $byEvent = []; $unattached = 0;
        foreach ($contributors as &$contributor) {
            $contributor['id'] = (int) $contributor['id']; $contributor['risk_delta'] = (int) $contributor['risk_delta'];
            $eventId = EvaluationService::contributorEventId((string) $contributor['label']);
            $contributor['event_id'] = $eventId;
            if ($eventId === null) $unattached++; else $byEvent[$eventId][] = $contributor;
        } unset($contributor);
        $timeline = []; $running = 0; $decoys = []; $profiles = [];
        foreach ($events as $event) {
            $eventId = (int) $event['id']; $metadata = self::metadata($event['metadata_json']);
            $attached = $byEvent[$eventId] ?? [];
            foreach ($attached as $item) $running = ThreatScoringService::bounded($running + (int) $item['risk_delta']);
            $timeline[] = ['evidence_id' => EvaluationService::evidenceId('EVT', $eventId), 'event_id' => $eventId, 'event_type' => $event['event_type'], 'severity' => $event['severity'], 'endpoint' => $event['endpoint'], 'http_method' => $event['http_method'], 'created_at' => $event['created_at'], 'metadata' => self::safeMetadataView($metadata), 'contributors' => $attached, 'score_after' => $running];
            if ($event['event_type'] === 'DECOY_ACCESSED') $decoys[(string) ($metadata['target_identifier'] ?? $metadata['decoy_identifier'] ?? 'UNKNOWN')] = true;
            if (in_array($event['event_type'], self::ADAPTIVE_TYPES, true)) $profiles[] = ['event_type' => $event['event_type'], 'profile' => $metadata['selected_profile'] ?? null, 'previous_profile' => $metadata['previous_profile'] ?? null, 'created_at' => $event['created_at']];
        }
        $stored = (int) $session['threat_score']; $reconstructed = ThreatScoringService::bounded((int)$contributorEvidence['points']);$truncated=(int)$contributorEvidence['total']>count($contributors);
        $session['id'] = (int) $session['id']; $session['user_id'] = $session['user_id'] === null ? null : (int) $session['user_id']; $session['threat_score'] = $stored; $session['request_count'] = (int) $session['request_count']; $session['evidence_id'] = EvaluationService::evidenceId('SEC', $id);
        return ['session' => $session, 'assessment' => ['contributor_count' => (int)$contributorEvidence['total'], 'contributors' => $contributors, 'reconstructed_score' => $reconstructed, 'integrity_status' => !$truncated&&$unattached === 0 && $reconstructed === $stored ? 'CONSISTENT' : 'WARNING', 'integrity_notes' => $truncated?'Contributor detail is bounded; full linkage was not displayed.':($unattached > 0 ? "{$unattached} contributor(s) could not be attached to an event." : ($reconstructed !== $stored ? 'Stored score differs from the bounded contributor sum.' : ''))], 'detection' => ['detection_latency_seconds' => EvaluationService::secondsBetween($timing['first_event'],$contributorEvidence['first_positive']), 'time_to_deception_seconds' => EvaluationService::secondsBetween($contributorEvidence['first_positive'],$timing['first_decoy']), 'time_to_honeytoken_seconds' => EvaluationService::secondsBetween($contributorEvidence['first_positive'],$timing['first_honeytoken'])], 'deception' => ['decoys' => array_keys($decoys), 'profiles' => $profiles, 'honeytoken_interactions' => (int)$timing['honeytoken_count']], 'timeline' => $timeline];
    }

    public static function timeline(array $filters, int $limit = 100): array
    {
        return self::timelineRows($filters, $limit, self::MAX_TIMELINE);
    }

    private static function timelineRows(array $filters, int $limit, int $maximum, ?array $types = null): array
    {
        [$where, $params] = self::eventWhere($filters, $types);
        $statement = Database::connection()->prepare("SELECT e.id,e.security_session_id,e.event_type,e.severity,e.endpoint,e.http_method,e.metadata_json,e.created_at FROM security_events e {$where} ORDER BY e.created_at DESC,e.id DESC LIMIT :limit");
        foreach ($params as $key => $value) $statement->bindValue($key, $value);
        $statement->bindValue('limit', min(max($limit, 1), $maximum), PDO::PARAM_INT); $statement->execute();
        $rows = $statement->fetchAll();
        $eventIds = array_map(static fn (array $r): int => (int) $r['id'], $rows); $contributors = [];
        if ($eventIds !== []) {
            $sessionIds = array_values(array_unique(array_filter(array_map(static fn (array $r): ?int => $r['security_session_id'] === null ? null : (int) $r['security_session_id'], $rows))));
            if ($sessionIds !== []) {
                $in = implode(',', array_fill(0, count($sessionIds), '?'));
                $query = Database::connection()->prepare("SELECT id,security_session_id,rule_code,label,risk_delta FROM security_score_contributors WHERE security_session_id IN ({$in}) ORDER BY id DESC LIMIT 1000"); $query->execute($sessionIds);
                foreach ($query->fetchAll() as $item) { $eventId = EvaluationService::contributorEventId($item['label']); if ($eventId !== null && in_array($eventId, $eventIds, true)) $contributors[$eventId][] = ['rule_code' => $item['rule_code'], 'risk_delta' => (int) $item['risk_delta']]; }
            }
        }
        return array_map(static function (array $row) use ($contributors): array { $id=(int)$row['id'];$metadata=self::metadata($row['metadata_json']);return ['evidence_id'=>EvaluationService::evidenceId('EVT',$id),'event_id'=>$id,'security_session_evidence_id'=>$row['security_session_id']===null?null:EvaluationService::evidenceId('SEC',(int)$row['security_session_id']),'domain'=>($metadata['category']??'UNKNOWN')==='LAB'?'CONTROLLED_LAB':'OPERATIONAL_SECURITY','event_type'=>$row['event_type'],'severity'=>$row['severity'],'endpoint'=>$row['endpoint'],'http_method'=>$row['http_method'],'created_at'=>$row['created_at'],'metadata'=>self::safeMetadataView($metadata),'contributors'=>$contributors[$id]??[]]; }, $rows);
    }

    public static function labEvaluation(array $filters): array
    {
        if (($filters['valid'] ?? true) !== true) return ['total_events' => 0, 'modules' => []];
        $database = Database::connection();
        $modules = $database->query('SELECT id,vulnerability_identifier,name,affected_component,state,is_active,mitigation,updated_at FROM vulnerability_modules ORDER BY vulnerability_identifier LIMIT ' . self::MAX_EXPORT)->fetchAll();
        [$where, $params] = self::eventWhere($filters, self::LAB_TYPES);
        $statement = $database->prepare("SELECT e.event_type,e.metadata_json,e.created_at FROM security_events e {$where} ORDER BY e.created_at DESC,e.id DESC LIMIT 500"); $statement->execute($params);
        $events = $statement->fetchAll();
        $stateRows = $database->query('SELECT m.vulnerability_identifier,c.from_state,c.to_state,c.reason,c.created_at FROM vulnerability_state_changes c JOIN vulnerability_modules m ON m.id=c.vulnerability_module_id ORDER BY c.created_at DESC,c.id DESC LIMIT 100')->fetchAll();
        $evaluations = [];
        foreach ($modules as $module) {
            $identifier = $module['vulnerability_identifier']; $counts = ['accesses'=>0,'interactions'=>0,'vulnerable_tests'=>0,'remediated_tests'=>0]; $vulnerable = $remediated = [];
            foreach ($events as $event) { $meta=self::metadata($event['metadata_json']); if (($meta['module_identifier']??null)!==$identifier) continue; if($event['event_type']==='LAB_MODULE_ACCESSED')$counts['accesses']++; if($event['event_type']==='LAB_VULNERABILITY_INTERACTION'){ $counts['interactions']++;$counts['vulnerable_tests']++;$vulnerable[]=$meta; } if($event['event_type']==='LAB_REMEDIATED_TEST'){ $counts['interactions']++;$counts['remediated_tests']++;$remediated[]=$meta; } }
            $history=array_values(array_filter($stateRows,static fn(array $r):bool=>$r['vulnerability_identifier']===$identifier));
            $evaluations[]=['module_identifier'=>$identifier,'name'=>$module['name'],'category'=>$module['affected_component'],'current_state'=>$module['state'],'is_active'=>(bool)$module['is_active'],...$counts,'state_change_count'=>count($history),'recent_state_changes'=>array_slice($history,0,10),'vulnerable_result'=>self::labObservation($identifier,$vulnerable,'VULNERABLE'),'remediated_result'=>self::labObservation($identifier,$remediated,'REMEDIATED'),'mitigation'=>$module['mitigation']];
        }
        return ['total_events'=>count($events),'modules'=>$evaluations];
    }

    public static function exportRows(string $type, array $filters, ?int $sessionId = null): ?array
    {
        if (self::exportFilterErrors($type, $filters) !== []) return null;
        if ($type === 'session_evidence') {
            if ($sessionId === null) {
                $latest = Database::connection()->query('SELECT id FROM security_sessions ORDER BY last_seen_at DESC,id DESC LIMIT 1')->fetchColumn();
                if ($latest === false) return [];
                $sessionId = (int) $latest;
            }
            $analysis = self::sessionAnalysis($sessionId);
            return $analysis === null ? null : [$analysis];
        }
        if ($type === 'lab_evaluation') return self::labEvaluation($filters)['modules'];
        if ($type === 'adaptive_timeline') return self::timelineRows($filters,self::MAX_EXPORT,self::MAX_EXPORT,self::ADAPTIVE_TYPES);
        if ($type === 'deception_interactions') return self::timelineRows($filters,self::MAX_EXPORT,self::MAX_EXPORT,['DECOY_ACCESSED','HONEYTOKEN_TRIGGERED']);
        if ($type === 'security_events') return self::timelineRows($filters,self::MAX_EXPORT,self::MAX_EXPORT);
        $database=Database::connection();
        if($type==='security_sessions'){[$where,$params]=self::sessionWhere($filters);$query=$database->prepare("SELECT s.id,s.user_id,s.threat_score,s.classification,s.request_count,s.first_seen_at,s.last_seen_at FROM security_sessions s {$where} ORDER BY s.last_seen_at DESC,s.id DESC LIMIT ".self::MAX_EXPORT);$query->execute($params);$rows=$query->fetchAll();return array_map(static function(array $r):array{$r['evidence_id']=EvaluationService::evidenceId('SEC',(int)$r['id']);unset($r['id']);return $r;},$rows);}
        if($type==='score_contributors'){[$where,$params]=self::sessionWhere($filters);$query=$database->prepare("SELECT c.id,c.security_session_id,c.rule_code,c.label,c.risk_delta,c.created_at FROM security_score_contributors c JOIN security_sessions s ON s.id=c.security_session_id {$where} ORDER BY c.created_at DESC,c.id DESC LIMIT ".self::MAX_EXPORT);$query->execute($params);$rows=$query->fetchAll();return array_map(static function(array $r):array{$r['contributor_evidence_id']=EvaluationService::evidenceId('CON',(int)$r['id']);$r['session_evidence_id']=EvaluationService::evidenceId('SEC',(int)$r['security_session_id']);unset($r['id'],$r['security_session_id']);return $r;},$rows);}
        return null;
    }

    private static function eventWhere(array $filters, ?array $types = null): array
    {
        if (($filters['valid'] ?? true) !== true) return ['WHERE 1=0', []];
        $clauses=[];$params=[];
        if($types!==null){$place=[];foreach($types as $i=>$type){$key="type_list_{$i}";$place[]=":{$key}";$params[$key]=$type;}$clauses[]='e.event_type IN ('.implode(',',$place).')';}
        foreach(['type'=>'e.event_type','severity'=>'e.severity'] as $key=>$column)if(($filters[$key]??'')!==''){$clauses[]="{$column}=:{$key}";$params[$key]=$filters[$key];}
        if(($filters['category']??'')!==''){$clauses[]="JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json,'$.category'))=:category";$params['category']=$filters['category'];}
        if(($filters['profile']??'')!==''){$clauses[]="COALESCE(JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json,'$.deception_profile')),JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json,'$.selected_profile'))) = :profile";$params['profile']=$filters['profile'];}
        if(($filters['module']??'')!==''){$clauses[]="JSON_UNQUOTE(JSON_EXTRACT(e.metadata_json,'$.module_identifier'))=:module";$params['module']=$filters['module'];}
        if(($filters['date_from']??'')!==''){$clauses[]='e.created_at>=:date_from';$params['date_from']=$filters['date_from'].' 00:00:00';}
        if(($filters['date_to']??'')!==''){$clauses[]='e.created_at<DATE_ADD(:date_to,INTERVAL 1 DAY)';$params['date_to']=$filters['date_to'].' 00:00:00';}
        if(($filters['threat_level']??'')!==''){$clauses[]='EXISTS(SELECT 1 FROM security_sessions fs WHERE fs.id=e.security_session_id AND fs.classification=:threat_level)';$params['threat_level']=$filters['threat_level'];}
        return [$clauses===[]?'':'WHERE '.implode(' AND ',$clauses),$params];
    }
    private static function sessionWhere(array $filters): array { if(($filters['valid']??true)!==true)return['WHERE 1=0',[]];$clauses=[];$params=[];if(($filters['threat_level']??'')!==''){$clauses[]='s.classification=:threat_level';$params['threat_level']=$filters['threat_level'];}if(($filters['date_from']??'')!==''){$clauses[]='s.first_seen_at>=:date_from';$params['date_from']=$filters['date_from'].' 00:00:00';}if(($filters['date_to']??'')!==''){$clauses[]='s.first_seen_at<DATE_ADD(:date_to,INTERVAL 1 DAY)';$params['date_to']=$filters['date_to'].' 00:00:00';}return[$clauses===[]?'':'WHERE '.implode(' AND ',$clauses),$params]; }
    private static function scalar(string $sql,array $params=[]):int{$statement=Database::connection()->prepare($sql);$statement->execute($params);return(int)$statement->fetchColumn();}
    private static function countTypes(array $types,array $filters):int{[$where,$params]=self::eventWhere($filters,$types);return self::scalar("SELECT COUNT(*) FROM security_events e {$where}",$params);}
    private static function validDate(string $date):bool{$parsed=DateTimeImmutable::createFromFormat('!Y-m-d',$date);return $parsed!==false&&$parsed->format('Y-m-d')===$date;}
    private static function metadata(?string $json):array{if($json===null||$json==='')return[];try{$decoded=json_decode($json,true,32,JSON_THROW_ON_ERROR);return is_array($decoded)?$decoded:[];}catch(Throwable){return[];}}
    private static function safeMetadataView(array $metadata):array{$allowed=['category','outcome','actor_user_id','target_type','target_identifier','decoy_identifier','honeytoken_identifier','deception_profile','selected_profile','previous_profile','threat_level','assessment_score','selection_reason','response_variant','module_identifier','module_state','technique','result_count','object_returned','input_length','lab_authorized'];return array_intersect_key($metadata,array_flip($allowed));}
    private static function groupPresenter(array $row):array{return['label'=>(string)$row['label'],'total'=>(int)$row['total']];}
    private static function increment(array &$counts,string $key):void{$counts[$key]=($counts[$key]??0)+1;}
    private static function mapCounts(array $counts):array{arsort($counts);return array_map(static fn(string $label,int $total):array=>['label'=>$label,'total'=>$total],array_keys($counts),array_values($counts));}
    private static function labObservation(string $identifier,array $evidence,string $state):string{if($evidence===[])return'INSUFFICIENT EVIDENCE';$last=end($evidence);if($identifier==='CHIM-VULN-002'&&isset($last['result_count']))return$state==='VULNERABLE'&&$last['result_count']>1?'Synthetic unauthorized rows were recorded as returned.':($state==='REMEDIATED'&&$last['result_count']<=1?'Synthetic unauthorized retrieval was recorded as prevented.':'Recorded test outcome requires contextual review.');if($identifier==='CHIM-VULN-001'&&array_key_exists('object_returned',$last))return(bool)$last['object_returned']?'A synthetic object was recorded as returned.':'Synthetic object access was recorded as denied.';if($identifier==='CHIM-VULN-003'&&isset($last['input_length']))return$state==='VULNERABLE'?'Controlled input was recorded as reflected in vulnerable mode.':'Controlled input was recorded as processed in remediated mode.';return'INSUFFICIENT EVIDENCE';}
}
