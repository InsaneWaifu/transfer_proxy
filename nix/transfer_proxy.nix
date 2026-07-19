{self}:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.transfer-proxy;

  statusType = lib.types.submodule {
    options = {
      type = lib.mkOption {
        type = lib.types.enum [ "static" "fetch_from" ];
        default = "static";
        description = "Status mode: 'static' for a fixed response, 'fetch_from' to proxy from another server.";
      };
      host = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "lobby.example.com";
        description = "Host to forward the status request to (fetch_from only).";
      };
      port = lib.mkOption {
        type = lib.types.ints.u16;
        default = 25565;
        description = "Port to forward the status request to (fetch_from only).";
      };
      rewriteAddress = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Rewrite the server address in the forwarded handshake (fetch_from only).";
      };
      cacheTtl = lib.mkOption {
        type = lib.types.nullOr lib.types.ints.positive;
        default = null;
        example = 30;
        description = "How long (seconds) to cache the fetched status. null = no caching (fetch_from only).";
      };
      json = lib.mkOption {
        type = lib.types.attrs;
        default = {
          version = { name = "1.21.5"; protocol = 770; };
          players = { max = 0; online = 0; };
          description.text = "A Minecraft Server";
        };
        description = "JSON status response body (static only).";
      };
      fakeProtocolVersion = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Replace the protocol version with the client's own version (static only).";
      };
    };
  };

  transferModeType = lib.types.submodule {
    options = {
      type = lib.mkOption {
        type = lib.types.enum [ "transfer" "proxy" "opportunistic" ];
        default = "transfer";
        description = "Transfer mode: 'transfer' (direct), 'proxy' (always proxy protocol), or 'opportunistic' (proxy protocol if supported).";
      };
      haproxy = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Send HAProxy PROXY protocol v2 header.";
      };
    };
  };

  destinationType = lib.types.submodule {
    options = {
      type = lib.mkOption {
        type = lib.types.enum [ "transfer" "kick" ];
        description = "Destination type: 'transfer' to forward to a server, 'kick' to reject the player.";
      };
      host = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "play.example.com";
        description = "Destination server host (transfer only).";
      };
      port = lib.mkOption {
        type = lib.types.ints.u16;
        default = 25565;
        description = "Destination server port (transfer only).";
      };
      rewriteAddress = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Rewrite the server address to the destination in the handshake (transfer only).";
      };
      transferMode = lib.mkOption {
        type = transferModeType;
        default = { type = "transfer"; };
        description = "How to transfer the player (transfer only).";
      };
      message = lib.mkOption {
        type = lib.types.attrs;
        default.text = "You have been kicked.";
        description = "Kick reason as a Minecraft JSON text component (kick only).";
      };
    };
  };

  routeType = lib.types.submodule {
    options = {
      "match" = lib.mkOption {
        type = lib.types.str;
        example = "lobby.example.com";
        description = "Hostname pattern. '*' = catch-all, '*.example.com' = subdomain.";
      };
      status = lib.mkOption {
        type = statusType;
        default = { type = "static"; };
      };
      destination = lib.mkOption {
        type = destinationType;
        default = { type = "transfer"; host = "localhost"; };
      };
    };
  };

  statusToYAML = s:
    if s.type == "static" then {
      inherit (s) type json;
      fake_protocol_version = s.fakeProtocolVersion;
    } else {
      inherit (s) type host port;
      rewrite_address = s.rewriteAddress;
    } // lib.optionalAttrs (s.cacheTtl != null) {
      cache_ttl = s.cacheTtl;
    };

  transferModeToYAML = tm:
    if tm.type == "transfer" then { type = "transfer"; }
    else { inherit (tm) type haproxy; };

  destinationToYAML = d:
    if d.type == "kick" then {
      inherit (d) type message;
    } else {
      inherit (d) type host port;
      rewrite_address = d.rewriteAddress;
      transfer_mode = transferModeToYAML d.transferMode;
    };

  routeToYAML = r: {
    "match" = r."match";
    status = statusToYAML r.status;
    destination = destinationToYAML r.destination;
  };

  configFile = pkgs.writeText "transfer-proxy-config.yaml"
    (lib.generators.toYAML {} {
      inherit (cfg) listen;
      routes = map routeToYAML cfg.routes;
    });

in
{
  options.services.transfer-proxy = {
    enable = lib.mkEnableOption "transfer_proxy";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.transfer_proxy;
      description = "The transfer_proxy package to use.";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0:25565";
      description = "Listen address (host:port).";
    };

    routes = lib.mkOption {
      type = lib.types.listOf routeType;
      default = [];
      description = "Route table. First match wins.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "transfer-proxy";
      description = "System user for the service.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "transfer-proxy";
      description = "System group for the service.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open TCP port 25565 in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.routes != [];
        message = "services.transfer-proxy.routes must not be empty.";
      }
    ];

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
    };

    users.groups.${cfg.group} = {};

    systemd.services.transfer-proxy = {
      description = "Minecraft Transfer Proxy";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/transfer_proxy ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;
        User = cfg.user;
        Group = cfg.group;

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        SystemCallFilter = [ "@system-service" "~@privileged" ];
        StateDirectory = "transfer-proxy";
      };
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ 25565 ];
    };
  };
}
