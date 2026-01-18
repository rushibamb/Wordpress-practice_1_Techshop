<?php
/**
 * Created by PhpStorm.
 * User: anandakrishna
 * Date: 2019-03-09
 * Time: 18:36
 */

namespace GetAstra\Middleware;

use Interop\Container\ContainerInterface;
use Slim\DeferredCallable;

class Responder
{
    /**
     * @var \Interop\Container\ContainerInterface
     */
    private $container;

    /**
     * HaltResponse constructor.
     *
     * @param \Interop\Container\ContainerInterface $container
     *
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
    }

    /**
     * HaltResponse middleware invokable class to halt the HTTP response when the X-HALT header is present in Response
     *
     * @param  \Psr\Http\Message\ServerRequestInterface $request PSR7 request
     * @param  \Psr\Http\Message\ResponseInterface $response PSR7 response
     * @param  callable $next Next middleware
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke($request, $response, $next)
    {

        $response = $next($request, $response);

        $status = $response->getStatusCode();
        $shouldHalt = in_array($status, array("200", "401", "201", "403")) || $response->hasHeader('X-Halt-Request');
        //$shouldHalt = $status !== "404" || $response->hasHeader('X-Halt-Request');

        $path = (string) $request->getUri()->getPath();
        $isApi = strpos($path, 'astra-api') !== false;

        if ($shouldHalt || $isApi) {
            $this->respond($response);
            exit;
        }

        return $response;
    }

    public function respond($response)
    {
        // Send response
        if (!headers_sent()) {
            // Headers
            foreach ($response->getHeaders() as $name => $values) {
                $first = stripos($name, 'Set-Cookie') === 0 ? false : true;
                foreach ($values as $value) {
                    header(sprintf('%s: %s', $name, $value), $first);
                    $first = false;
                }
            }
            // Set the status _after_ the headers, because of PHP's "helpful" behavior with location headers.
            // See https://github.com/slimphp/Slim/issues/1730
            // Status
            header(sprintf(
                'HTTP/%s %s %s',
                $response->getProtocolVersion(),
                $response->getStatusCode(),
                $response->getReasonPhrase()
            ), true, $response->getStatusCode());
        }

        $body = $response->getBody();

        if ($body->isSeekable()) {
            $body->rewind();
        }

        $settings = $this->container->get('settings');
        $chunkSize = $settings['responseChunkSize'];
        $contentLength = $response->getHeaderLine('Content-Length');

        if (!$contentLength) {
            $contentLength = $body->getSize();
        }
        if (isset($contentLength)) {
            $amountToRead = $contentLength;
            while ($amountToRead > 0 && !$body->eof()) {
                $data = $body->read(min((int)$chunkSize, (int)$amountToRead));
                echo $data;
                $amountToRead -= strlen($data);
                if (connection_status() != CONNECTION_NORMAL) {
                    break;
                }
            }
        } else {
            while (!$body->eof()) {
                echo $body->read((int)$chunkSize);
                if (connection_status() != CONNECTION_NORMAL) {
                    break;
                }
            }
        }
    }

}