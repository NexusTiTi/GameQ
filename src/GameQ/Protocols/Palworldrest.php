<?php

/**
 * This file is part of GameQ.
 *
 * GameQ is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GameQ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace GameQ\Protocols;

use GameQ\Exception\Protocol as Exception;
use GameQ\Result;
use GameQ\Server;

/**
 * Palworld Protocol Class
 *
 * Protocol for palworld by using the REST Api
 *
 * @package GameQ\Protocols
 * @author  NexusTiTi
 */
class Palworldrest extends Http
{
    /**
     * The protocol being used
     *
     * @var string
     */
    protected $protocol = 'palwordrest';

    /**
     * Longer string name of this protocol class
     *
     * @var string
     */
    protected $name_long = 'Palworld';

    /**
     * String name of this protocol class
     *
     * @var string
     */
    protected $name = 'palwordrest';

    /**
     * The difference between the client port and query port
     *
     * @var int
     */
    protected $port_diff = 1;

    /**
     * User name for authentication
     * 
     * @var string
     */
    protected $username = 'admin';

    /**
     * Holds the server ip so we can overwrite it back
     *
     * @var string
     */
    protected $serverIp = null;

    /**
     * Holds the server port query so we can overwrite it back
     *
     * @var string
     */
    protected $serverPortQuery = null;

    /**
     * Holds the server data so we can overwrite it back
     *
     * @var string
     */
    protected $server_data = null;

    /**
     * Process the response from the REST API and filter Palworld-specific server data
     *
     * @return array
     * @throws Exception
     */
    public function processResponse()
    {
        // Make sure we have any players
        if (empty($this->server_data)) {
            return [];
        }

        $list = json_decode($this->server_data, true);

        $result = new Result();
        $result->add('players', $list['players']);

        return $result->fetch();
    }

    /**
     * Called before sending the request
     *
     * @param Server $server
     */
    public function beforeSend($server)
    {
        $this->serverIp = $server->ip();
        $this->serverPortQuery = $server->portQuery();

        if (!$server->getOption('password')) {
            return;
        }

        // Query for server data
        $this->server_data = $this->queryServers($server->getOption('password'));
    }

    /**
     * Query the REST API for data
     * 
     * @param string $password
     * @return array|null
     */
    protected function queryServers(string $password)
    {
        $url = "http://" . $this->serverIp . ":" . $this->serverPortQuery . "/v1/api/players";
        $headers = [
            'Accept: application/json',
            'Authorization: Basic ' . base64_encode('admin:' . $password)
        ];

        return $this->httpRequest($url, $headers);
    }

    /**
     * Execute an HTTP request
     * 
     * @param string $url
     * @param array $headers
     * @return array|null
     */
    protected function httpRequest($url, $headers)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HTTP_VERSION , CURL_HTTP_VERSION_1_1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        $response = curl_exec($ch);
        curl_close($ch);

        if (!$response) {
            return null;
        }

        $this->packets_response[] = $response;

        return $response;
    }
}
