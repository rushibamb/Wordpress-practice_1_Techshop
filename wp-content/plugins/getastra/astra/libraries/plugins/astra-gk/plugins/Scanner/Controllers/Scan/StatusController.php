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
 * @date   2019-03-14
 */

namespace GetAstra\Plugins\Scanner\Controllers\Scan;

use GetAstra\Plugins\Scanner\Models\ScanStatus;
use GetAstra\Plugins\Scanner\Transformers\ScanStatusTransformer;
use Interop\Container\ContainerInterface;
use League\Fractal\Resource\Collection;
use Slim\Http\Request;
use Slim\Http\Response;

class StatusController
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
     * Scan Status constructor.
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
     * Return List of Options
     *
     * @param \Slim\Http\Request $request
     * @param \Slim\Http\Response $response
     * @param array $args
     *
     * @return \Slim\Http\Response
     */
    public function index(Request $request, Response $response, array $args)
    {
        $builder = ScanStatus::query()->limit(100)->orderBy('id', 'DESC');

        if ($limit = $request->getParam('limit')) {
            $builder->limit($limit);
        }

        if ($offset = $request->getParam('offset')) {
            $builder->offset($offset);
        }

        $statusCount = $builder->count();
        $status = $builder->get();

        $data = $this->fractal->createData(new Collection($status,
            new ScanStatusTransformer()))->toArray();

        return $response->withJson(['status' => $data['data'], 'statusCount' => $statusCount]);
    }


    public function destroy(Request $request, Response $response, array $args)
    {
        ScanStatus::query()->truncate();

        return $response->withJson([], 200);
    }

}