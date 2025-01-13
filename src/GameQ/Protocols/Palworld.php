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

/**
 * Palworld Protocol Class
 *
 * Extends the EOS protocol and adds Palworld-specific server response processing.
 *
 * @package GameQ\Protocols
 * @author  NexusTiTi
 */
class Palworld extends Eos
{
    /**
     * The protocol being used
     *
     * @var string
     */
    protected $protocol = 'palword';

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
    protected $name = 'palworld';

    /**
     * Grant type used for authentication
     *
     * @var string
     */
    protected $grant_type = 'client_credentials';

    /**
     * Deployment ID for the game or application
     *
     * @var string
     */
    protected $deployment_id = '0a18471f93d448e2a1f60e47e03d3413';

    /**
     * User ID for authentication
     *
     * @var string
     */
    protected $user_id = 'xyza78916PZ5DF0fAahu4tnrKKyFpqRE';

    /**
     * User secret key for authentication
     *
     * @var string
     */
    protected $user_secret = 'j0NapLEPm3R3EOrlQiM8cRLKq3Rt02ZVVwT0SkZstSg';

    /**
     * Process the response from the EOS API and filter Palworld-specific server data
     *
     * @return array
     * @throws Exception
     */
    public function processResponse()
    {
        $serverData = parent::processResponse();

        // Filter by port to match server sessions
        $filtered = array_filter($serverData, function ($session) {
            return $session['attributes']['GAMESERVER_PORT_l'] === $this->serverPortQuery;
        });

        if (!$filtered) {
            throw new Exception('No matching sessions found for the specified port.');
        }

        $session = reset($filtered);

        $result = new Result();

        // Add server items to the result object
        $result->add('hostname', $this->getAttribute($session['attributes'], 'NAME_s', 'Unknown'));
        $result->add('mapname', $this->getAttribute($session['attributes'], 'MAPNAME_s', 'Unknown'));
        $result->add('password', $this->getAttribute($session['attributes'], 'ISPASSWORD_b', false));
        $result->add('numplayers', $this->getAttribute($session, 'totalPlayers', 0));
        $result->add('maxplayers', $this->getAttribute($session['settings'], 'maxPublicPlayers', 0));
        $result->add('anticheat', $this->getAttribute($session['attributes'], 'BANTICHEATPROTECTED_b', false));
        $result->add('day', $this->getAttribute($session['attributes'], 'DAYS_l', 0));
        $result->add('version', $this->getAttribute($session['attributes'], 'VERSION_s', 'Unknown'));

        // Return the final result
        return $result->fetch();
    }
}
