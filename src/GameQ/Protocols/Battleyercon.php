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

use GameQ\Buffer;
use GameQ\Exception\Protocol as Exception;
use GameQ\Protocol;
use GameQ\Result;

/**
 * BattlEye RCon Protocol Class
 *
 * Queries a BattlEye RCon (BEServer) enabled game server (Arma 2/3, DayZ, ...) for its player list.
 *
 * The RCon password is mandatory and has to be passed as a server option:
 *
 *  $gq->addServer([
 *      'type'    => 'battleyercon',
 *      'host'    => '127.0.0.1:2302',
 *      'options' => [
 *          'query_port'    => 2306,          // The BEServer "RConPort", no standard offset exists
 *          'rcon_password' => 'yourpassword',
 *          'commands'      => ['players'],   // Optional, extra commands are returned as raw text
 *      ],
 *  ]);
 *
 * Protocol reference: BattlEye "BERConProtocol.txt"
 *
 *  Header: 'B'(0x42) 'E'(0x45) <4 byte CRC32 checksum of the following bytes, little endian> 0xFF
 *  Login:   0x00 <password>              -> 0x00 <0x01 = success | 0x00 = failure>
 *  Command: 0x01 <sequence> <command>    -> 0x01 <sequence> [0x00 <total> <index>] <data>
 *  Message: 0x02 <sequence> <message>    (server initiated, ignored here)
 *
 * @package GameQ\Protocols
 */
class Battleyercon extends Protocol
{
    /**
     * Packet types as defined by the BattlEye RCon protocol
     */
    const PACKET_TYPE_LOGIN = 0x00;

    const PACKET_TYPE_COMMAND = 0x01;

    const PACKET_TYPE_MESSAGE = 0x02;

    /**
     * The command used to grab the player list
     */
    const COMMAND_PLAYERS = 'players';

    /**
     * Array of packets we want to look up.  Filled in by the constructor since all of them are checksum'd
     *
     * @var array
     */
    protected $packets = [];

    /**
     * The query protocol used to make the call
     *
     * @var string
     */
    protected $protocol = 'battleyercon';

    /**
     * String name of this protocol class
     *
     * @var string
     */
    protected $name = 'battleyercon';

    /**
     * Longer string name of this protocol class
     *
     * @var string
     */
    protected $name_long = "BattlEye RCon";

    /**
     * The transport used by the BattlEye RCon protocol
     *
     * @var string
     */
    protected $transport = self::TRANSPORT_UDP;

    /**
     * The RCon port is defined in the BEServer config and has no standard offset
     *
     * @var int
     */
    protected $port_diff = 0;

    /**
     * The RCon password used to log into the server
     *
     * @var string
     */
    protected $password = '';

    /**
     * The commands sent to the server.  The sequence number of a command is its index in this list
     *
     * @var array
     */
    protected $commands = [self::COMMAND_PLAYERS];

    /**
     * Holds the login state.  Null when unknown (i.e. no challenge was made), false when the login was rejected
     *
     * @var bool|null
     */
    protected $authenticated = null;

    /**
     * Normalize settings for this protocol
     *
     * @var array
     */
    protected $normalize = [
        // General
        'general' => [
            // target       => source
            'numplayers' => 'numplayers',
        ],
        // Individual
        'player'  => [
            'name' => 'name',
            'ping' => 'ping',
        ],
    ];

    /**
     * Build the packets we need to send, they depend on the options given for this server
     *
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        parent::__construct($options);

        // Grab the password, it is needed to build the login packet
        if (array_key_exists('rcon_password', $options)) {
            $this->password = (string)$options['rcon_password'];
        } elseif (array_key_exists('password', $options)) {
            $this->password = (string)$options['password'];
        }

        // Allow the list of commands to be overloaded, the player list is always queried
        if (array_key_exists('commands', $options) && !empty($options['commands'])) {
            $this->commands = array_values(array_unique(array_merge(
                [self::COMMAND_PLAYERS],
                (array)$options['commands']
            )));
        }

        // The login packet doubles as the challenge packet, it has to be sent before anything else
        $this->packets[self::PACKET_CHALLENGE] = $this->buildPacket(self::PACKET_TYPE_LOGIN, $this->password);

        // Each command gets its own packet, the sequence number is the index of the command
        foreach ($this->commands as $sequence => $command) {
            $this->packets[$command] = $this->buildPacket(
                self::PACKET_TYPE_COMMAND,
                chr($sequence % 256) . $command
            );
        }
    }

    /**
     * Handle the login response before the actual commands are sent
     *
     * @param Buffer $challenge_buffer
     *
     * @return bool
     */
    public function challengeParseAndApply(Buffer $challenge_buffer)
    {
        $packet = $this->unwrapPacket($challenge_buffer->getData());

        // We could not make any sense out of the response, let processResponse deal with it
        if ($packet === null || $packet['type'] !== self::PACKET_TYPE_LOGIN) {
            return false;
        }

        // 0x01 means the password was accepted
        $this->authenticated = ($packet['data'] === "\x01");

        if (!$this->authenticated) {
            // The server dropped us, do not bother sending the commands
            $this->packets = [self::PACKET_CHALLENGE => $this->packets[self::PACKET_CHALLENGE]];
        }

        return $this->authenticated;
    }

    /**
     * Process the response
     *
     * @return array
     * @throws Exception
     */
    public function processResponse()
    {
        // The login was rejected during the challenge, no point in going any further
        if ($this->authenticated === false) {
            throw new Exception(__METHOD__ . " RCon login was rejected by the server, check the password.");
        }

        if (empty($this->packets_response)) {
            throw new Exception(__METHOD__ . " No response from the server. Server might be offline.");
        }

        // Holds the (re-assembled) response for each sequence number we sent
        $responses = $this->collectResponses();

        if (empty($responses)) {
            throw new Exception(__METHOD__ . " No usable response from the server.");
        }

        $result = new Result();

        // Map the sequence numbers back onto the commands we sent
        foreach ($responses as $sequence => $parts) {
            // Re-assemble multi packet responses in the correct order
            ksort($parts);

            if (!array_key_exists($sequence, $this->commands)) {
                continue;
            }

            $command = $this->commands[$sequence];
            $data = implode('', $parts);

            if ($command === self::COMMAND_PLAYERS) {
                $this->processPlayers($result, $data);
            } else {
                // Any other command is handed back as-is, there is nothing generic to parse
                $result->add($command, $data);
            }
        }

        return $result->fetch();
    }

    /**
     * Walk over the raw packets we received and group the command payloads by sequence number
     *
     * @return array
     * @throws Exception
     */
    protected function collectResponses()
    {
        $responses = [];

        foreach ($this->packets_response as $response) {
            $packet = $this->unwrapPacket($response);

            // Not a valid BattlEye packet, skip it
            if ($packet === null) {
                continue;
            }

            // A login response made it in here, make sure it was not a rejection
            if ($packet['type'] === self::PACKET_TYPE_LOGIN && $packet['data'] !== "\x01") {
                throw new Exception(__METHOD__ . " RCon login was rejected by the server, check the password.");
            }

            // Server initiated messages (chat, kicks, ...) are of no use for a query, drop them
            if ($packet['type'] !== self::PACKET_TYPE_COMMAND) {
                continue;
            }

            $this->addResponsePart($responses, $packet['data']);
        }

        return $responses;
    }

    /**
     * Wrap a payload into a BattlEye RCon packet
     *
     * @param int    $type
     * @param string $payload
     *
     * @return string
     */
    protected function buildPacket($type, $payload = '')
    {
        // The checksum covers everything after it, starting with the 0xFF separator
        $data = "\xFF" . chr($type) . $payload;

        return "BE" . pack('V', crc32($data)) . $data;
    }

    /**
     * Validate a raw packet and split it into its type and payload
     *
     * @param string $packet
     *
     * @return array|null Null when the packet is not a valid BattlEye RCon packet
     */
    protected function unwrapPacket($packet)
    {
        // Header (7 bytes) plus at least one byte of payload
        if (strlen($packet) < 8 || substr($packet, 0, 2) !== 'BE' || $packet[6] !== "\xFF") {
            return null;
        }

        $checksum = unpack('Vchecksum', substr($packet, 2, 4));
        $payload = substr($packet, 6);

        // Drop packets which did not survive the trip, compare unsigned to stay 32bit safe
        if (sprintf('%u', $checksum['checksum']) !== sprintf('%u', crc32($payload))) {
            return null;
        }

        return [
            'type' => ord($payload[1]),
            'data' => substr($payload, 2),
        ];
    }

    /**
     * Add the payload of a command packet to the responses, taking multi packet responses into account
     *
     * @param array  $responses
     * @param string $data
     */
    protected function addResponsePart(array &$responses, $data)
    {
        // A command response always carries the sequence number of the command it belongs to
        if (strlen($data) < 1) {
            return;
        }

        $sequence = ord($data[0]);
        $data = substr($data, 1);

        // Multi packet response, the payload is prefixed with 0x00 <total packets> <packet index>
        if (strlen($data) >= 3 && $data[0] === "\x00") {
            $index = ord($data[2]);
            $data = substr($data, 3);
        } else {
            $index = 0;
        }

        if (!array_key_exists($sequence, $responses)) {
            $responses[$sequence] = [];
        }

        $responses[$sequence][$index] = $data;
    }

    /**
     * Parse the output of the "players" command
     *
     * Players on server:
     * [#] [IP Address]:[Port] [Ping] [GUID] [Name]
     * --------------------------------------------------
     * 0   127.0.0.1:2304        32   80a5885ebe2420bab5e158a310fcbc7d(OK) Player Name
     * (1 players in total)
     *
     * @param Result $result
     * @param string $data
     */
    protected function processPlayers(Result $result, $data)
    {
        $players = [];
        $total = null;

        foreach (preg_split('/\r\n|\n|\r/', $data) as $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            // The server tells us how many players it thinks are connected
            if (preg_match('/^\((?<total>\d+) players? in total\)$/i', $line, $matches)) {
                $total = (int)$matches['total'];
                continue;
            }

            $matched = preg_match(
                '/^(?<id>\d+)\s+(?<ip>.+):(?<port>\d+)\s+(?<ping>-?\d+)\s+'
                . '(?<guid>[0-9a-f]*)\((?<verified>[^)]*)\)\s*(?<name>.*)$/i',
                $line,
                $matches
            );

            // Header, separator or anything else we do not care about
            if (!$matched) {
                continue;
            }

            $name = $matches['name'];

            // Players who have not finished connecting are flagged as being in the lobby
            $lobby = (substr($name, -8) === ' (Lobby)');

            if ($lobby) {
                $name = substr($name, 0, -8);
            }

            $players[] = [
                'id'       => (int)$matches['id'],
                'ip'       => $matches['ip'],
                'port'     => (int)$matches['port'],
                'ping'     => (int)$matches['ping'],
                'guid'     => $matches['guid'],
                'verified' => (strtoupper($matches['verified']) === 'OK'),
                'lobby'    => $lobby,
                'name'     => $name,
            ];
        }

        $result->add('numplayers', is_null($total) ? count($players) : $total);

        foreach ($players as $player) {
            foreach ($player as $key => $value) {
                $result->addPlayer($key, $value);
            }
        }
    }
}
