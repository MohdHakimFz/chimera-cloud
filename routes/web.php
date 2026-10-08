<?php

declare(strict_types=1);

use App\Controllers\AdminController;
use App\Controllers\ActivityController;
use App\Controllers\ApiController;
use App\Controllers\AuthController;
use App\Controllers\DashboardController;
use App\Controllers\DocumentController;
use App\Controllers\HomeController;
use App\Controllers\ProfileController;
use App\Controllers\SecurityController;
use App\Controllers\SecurityApiController;
use App\Controllers\DecoyController;
use App\Controllers\DeceptionController;
use App\Controllers\DeceptionApiController;
use App\Controllers\ThreatAssessmentController;
use App\Controllers\ThreatAssessmentApiController;
use App\Controllers\AdaptiveDeceptionController;
use App\Controllers\AdaptiveDeceptionApiController;
use App\Controllers\LabController;
use App\Controllers\LabManagementController;
use App\Controllers\SecurityAnalyticsController;
use App\Controllers\SecurityAnalyticsApiController;
use App\Controllers\DeploymentReadinessController;
use App\Middleware\Authenticate;
use App\Middleware\GuestOnly;
use App\Middleware\RequireRole;
use App\Middleware\VerifyCsrf;
use App\Middleware\RequireLabEnabled;

$router = $app->router();

$router->get('/', [HomeController::class, 'index']);
$router->get('/about', [HomeController::class, 'about']);
$router->get('/admin-old', [DecoyController::class, 'show']);
$router->get('/internal', [DecoyController::class, 'show']);
$router->get('/api/debug', [DecoyController::class, 'show']);
$router->get('/api/debug/verify', [DecoyController::class, 'honeytoken']);
$router->get('/lab', [LabController::class, 'index'], [RequireLabEnabled::class]);
$router->get('/lab/robots.txt', [LabController::class, 'robots'], [RequireLabEnabled::class]);
$router->get('/lab/sqli', [LabController::class, 'sqli'], [RequireLabEnabled::class]);
$router->get('/lab/idor', [LabController::class, 'idor'], [RequireLabEnabled::class]);
$router->get('/lab/xss', [LabController::class, 'xss'], [RequireLabEnabled::class]);

$router->get('/login', [AuthController::class, 'showLogin'], [GuestOnly::class]);
$router->post('/login', [AuthController::class, 'login'], [GuestOnly::class, VerifyCsrf::class]);
$router->get('/register', [AuthController::class, 'showRegister'], [GuestOnly::class]);
$router->post('/register', [AuthController::class, 'register'], [GuestOnly::class, VerifyCsrf::class]);
$router->post('/logout', [AuthController::class, 'logout'], [Authenticate::class, VerifyCsrf::class]);

$router->get('/dashboard', [DashboardController::class, 'index'], [Authenticate::class]);
$router->get('/profile', [ProfileController::class, 'show'], [Authenticate::class]);
$router->post('/profile', [ProfileController::class, 'update'], [Authenticate::class, VerifyCsrf::class]);
$router->get('/documents', [DocumentController::class, 'index'], [Authenticate::class]);
$router->post('/documents', [DocumentController::class, 'upload'], [Authenticate::class, VerifyCsrf::class]);
$router->get('/documents/{id}', [DocumentController::class, 'show'], [Authenticate::class]);
$router->get('/documents/{id}/download', [DocumentController::class, 'download'], [Authenticate::class]);
$router->post('/documents/{id}/delete', [DocumentController::class, 'delete'], [Authenticate::class, VerifyCsrf::class]);
$router->get('/activity', [ActivityController::class, 'index'], [Authenticate::class]);

$router->get('/api/me', [ApiController::class, 'me'], [Authenticate::class]);
$router->get('/api/documents', [ApiController::class, 'documents'], [Authenticate::class]);
$router->get('/api/documents/{id}', [ApiController::class, 'document'], [Authenticate::class]);

$router->get('/admin', [AdminController::class, 'index'], [new RequireRole(['admin'])]);
$router->get('/security', [SecurityController::class, 'index'], [new RequireRole(['security_admin'])]);
$router->get('/security/events/{id}', [SecurityController::class, 'show'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/events', [SecurityApiController::class, 'events'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/events/{id}', [SecurityApiController::class, 'event'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/summary', [SecurityApiController::class, 'summary'], [new RequireRole(['security_admin'])]);
$router->get('/security/deception', [DeceptionController::class, 'index'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/deception/summary', [DeceptionApiController::class, 'summary'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/decoys', [DeceptionApiController::class, 'decoys'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/honeytokens', [DeceptionApiController::class, 'honeytokens'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/deception/events', [DeceptionApiController::class, 'events'], [new RequireRole(['security_admin'])]);
$router->get('/security/threats', [ThreatAssessmentController::class, 'index'], [new RequireRole(['security_admin'])]);
$router->get('/security/threats/{id}', [ThreatAssessmentController::class, 'show'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/sessions', [ThreatAssessmentApiController::class, 'sessions'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/sessions/{id}', [ThreatAssessmentApiController::class, 'session'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/threat-summary', [ThreatAssessmentApiController::class, 'summary'], [new RequireRole(['security_admin'])]);
$router->get('/security/adaptive', [AdaptiveDeceptionController::class, 'index'], [new RequireRole(['security_admin'])]);
$router->get('/security/adaptive/{id}', [AdaptiveDeceptionController::class, 'show'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/adaptive/summary', [AdaptiveDeceptionApiController::class, 'summary'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/sessions/{id}/deception', [AdaptiveDeceptionApiController::class, 'session'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/adaptive/events', [AdaptiveDeceptionApiController::class, 'events'], [new RequireRole(['security_admin'])]);
$router->get('/security/lab', [LabManagementController::class, 'index'], [new RequireRole(['security_admin'])]);
$router->post('/security/lab/modules/{id}/state', [LabManagementController::class, 'changeState'], [new RequireRole(['security_admin']), VerifyCsrf::class]);
$router->get('/security/analytics', [SecurityAnalyticsController::class, 'index'], [new RequireRole(['security_admin'])]);
$router->get('/security/analytics/sessions/{id}', [SecurityAnalyticsController::class, 'session'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/analytics/summary', [SecurityAnalyticsApiController::class, 'summary'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/analytics/timeline', [SecurityAnalyticsApiController::class, 'timeline'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/analytics/sessions/{id}', [SecurityAnalyticsApiController::class, 'session'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/analytics/lab', [SecurityAnalyticsApiController::class, 'lab'], [new RequireRole(['security_admin'])]);
$router->get('/api/security/analytics/export', [SecurityAnalyticsApiController::class, 'export'], [new RequireRole(['security_admin'])]);
$router->get('/security/deployment-readiness', [DeploymentReadinessController::class, 'index'], [new RequireRole(['security_admin'])]);
