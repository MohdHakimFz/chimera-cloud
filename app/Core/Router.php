<?php

declare(strict_types=1);

namespace App\Core;

use App\Middleware\Middleware;

final class Router
{
    private array $routes = [];

    public function get(string $path, array|callable $handler, array $middleware = []): void
    {
        $this->add('GET', $path, $handler, $middleware);
    }

    public function post(string $path, array|callable $handler, array $middleware = []): void
    {
        $this->add('POST', $path, $handler, $middleware);
    }

    private function add(string $method, string $path, array|callable $handler, array $middleware): void
    {
        $normalized = $path === '/' ? '/' : rtrim($path, '/');
        $parameterNames = [];
        $quoted = preg_quote($normalized, '#');
        $pattern = preg_replace_callback('/\\\\\{([A-Za-z_][A-Za-z0-9_]*)\\\\\}/', static function (array $matches) use (&$parameterNames): string {
            $parameterNames[] = $matches[1];
            return '(?P<' . $matches[1] . '>[1-9][0-9]*)';
        }, $quoted);

        $this->routes[$method][] = [
            'path' => $normalized,
            'pattern' => '#^' . $pattern . '$#',
            'parameterNames' => $parameterNames,
            'handler' => $handler,
            'middleware' => $middleware,
        ];
    }

    public function dispatch(Request $request): void
    {
        $route = null;
        $parameters = [];
        foreach ($this->routes[$request->method()] ?? [] as $candidate) {
            if (!preg_match($candidate['pattern'], $request->path(), $matches)) {
                continue;
            }
            $route = $candidate;
            foreach ($candidate['parameterNames'] as $name) {
                $parameters[$name] = $matches[$name];
            }
            break;
        }

        if ($route === null) {
            $allowed=[];
            foreach($this->routes as$method=>$candidates){if($method===$request->method())continue;foreach($candidates as$candidate){if(preg_match($candidate['pattern'],$request->path())===1){$allowed[]=$method;break;}}}
            if($allowed!==[]){header('Allow: '.implode(', ',array_unique($allowed)));if($request->isApi())Response::json(['error'=>['code'=>'METHOD_NOT_ALLOWED','message'=>'Method not allowed.']],405);Response::abort(405,'The requested method is not allowed.');}
            if ($request->isApi()) {
                Response::json(['error' => ['code' => 'NOT_FOUND', 'message' => 'Resource not found.']], 404);
            }
            Response::abort(404, 'The requested page could not be found.');
        }

        $request->setRouteParameters($parameters);

        $destination = function (Request $request) use ($route): void {
            $handler = $route['handler'];
            if (is_array($handler) && is_string($handler[0])) {
                $handler = [new $handler[0](), $handler[1]];
            }
            $handler($request);
        };

        $pipeline = array_reduce(
            array_reverse($route['middleware']),
            static function (callable $next, string|Middleware $middleware): callable {
                return static function (Request $request) use ($middleware, $next): void {
                    $instance = is_string($middleware) ? new $middleware() : $middleware;
                    $instance->handle($request, $next);
                };
            },
            $destination
        );

        $pipeline($request);
    }
}
