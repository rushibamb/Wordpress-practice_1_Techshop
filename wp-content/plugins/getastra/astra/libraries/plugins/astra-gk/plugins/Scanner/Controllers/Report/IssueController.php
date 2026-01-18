<?php
/**
 * This file is part of the Astra Security Suite
 *
 *  Copyright (c) 2019 (https://www.getastra.com/)
 *
 *  For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 *
 */

/**
 *
 *
 * @author HumansofAstra-WZ <help@getastra.com>
 * @date   2019-03-25
 */

namespace GetAstra\Plugins\Scanner\Controllers\Report;

use GetAstra\Plugins\Scanner\Helpers\StatusHelper;
use GetAstra\Plugins\Scanner\Models\Issue;
use GetAstra\Plugins\Scanner\Transformers\IssueTransformer;
use Interop\Container\ContainerInterface;
use League\Fractal\Resource\Collection;
use Slim\Http\Request;
use Slim\Http\Response;

class IssueController
{

    /** @var \Illuminate\Database\Capsule\Manager */
    protected $db;
    /** @var \GetAstra\Services\Auth\Auth */
    protected $auth;
    /** @var \League\Fractal\Manager */
    protected $fractal;
    /** @var \Interop\Container\ContainerInterface */
    protected $container;


    /**
     * Scan Issue constructor.
     *
     * @param \Interop\Container\ContainerInterface $container
     *
     * @internal param $auth
     */
    public function __construct(ContainerInterface $container)
    {
        $this->auth = $container->get('auth');
        $this->fractal = $container->get('fractal');
        $this->db = $container->get('db');
        $this->container = $container;
    }

    /**
     * Return List of Issues
     *
     * @param \Slim\Http\Request $request
     * @param \Slim\Http\Response $response
     * @param array $args
     *
     * @return \Slim\Http\Response
     */
    public function index(Request $request, Response $response, array $args)
    {
        $builder = Issue::query()->limit(100)->orderBy('id', 'DESC');

        if ($limit = $request->getParam('limit')) {
            $builder->limit($limit);
        }

        if ($offset = $request->getParam('offset')) {
            $builder->offset($offset);
        }

        $issueCount = $builder->count();
        $issue = $builder->get();

        $data = $this->fractal->createData(new Collection($issue,
            new IssueTransformer()))->toArray();

        return $response->withJson(['issues' => $data['data'], 'issueCount' => $issueCount]);
    }


    public function destroy(Request $request, Response $response, array $args)
    {
        Issue::truncate();

        return $response->withJson([], 200);
    }

    /**
     * Receives a delete file request
     * @param Request $request
     * @param Response $response
     * @param array $args
     * @return Response
     */
    public function deleteFile(Request $request, Response $response, array $args)
    {
        $requestData = $request->getParsedBody();
        if(!isset($requestData['deleteKey'], $requestData['path'])) {
            StatusHelper::add(4, 'error', 'Delete file request is missing deleteKey or path');
            $responseStatus = 400;
            $responseData = ['error' => 'Delete file request is missing deleteKey or path'];
        } else {
            $issue = Issue::query()
                ->where('deleteKey', $requestData['deleteKey'])
                ->where('path', $requestData['path'])
                ->get();
            if(($count = $issue->count()) > 0) {
                if($count === 1) {
                    $path = $issue->first()->path;
                    error_log('The filepath is '.$path);
                    clearstatcache(TRUE, $path);
                    if(is_writable($path)) {
                        error_log("$path was writable");
                        if(unlink($path)) {
                            $responseStatus = 200;
                            $responseData = ['success' => true];
                        } else {
                            $responseStatus = 500;
                            $responseData = ['error' => 'An unknown error was encountered deleting the file.'];
                        }
                    } else {
                        error_log("$path was not writable");
                        $responseStatus = 500;
                        $responseData = ['error' => 'File permissions prevent the file from being deleted.'];
                    }
                } else {
                    $responseStatus = 400;
                    $responseData = ['error' => 'deleteKey & path have matched more than one issue'];
                }
            } else {
                $responseStatus = 400;
                $responseData = ['error' => 'deleteKey & path did not match any issue'];
            }
        }
        $response = $response->withStatus($responseStatus);
        $response = $response->withJson($responseData);
        return $response;
    }

}