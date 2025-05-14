% 1U CubeSat daily passes + latency & RTT over Svalbard station
clear; clc;

% Constants
Re    = 6371e3;             % Earth radius [m]
h     = 500e3;              % Orbit altitude [m]
a     = Re + h;             % Semi-major axis [m]
mu    = 3.986e14;           % Earth's gravitational parameter [m^3/s^2]
incl  = deg2rad(98);        % Orbit inclination [rad]
omega = 7.292115e-5;        % Earth rotation rate [rad/s]
c     = 3e8;                % Speed of light [m/s]

% Ground station ECEF (Svalbard)
lat0 = deg2rad(78.2297722);
lon0 = deg2rad(15.4077861);
gs   = [Re*cos(lat0)*cos(lon0);
        Re*cos(lat0)*sin(lon0);
        Re*sin(lat0)];

% Orbit period
Torb = 2*pi*sqrt(a^3/mu);

% Simulation settings
dt   = 10;                  % time step [s]
t    = 0:dt:24*3600;        % one day [s]
N    = numel(t);

% Preallocate
elev    = zeros(1,N);
latency = zeros(1,N);

% Compute elevation & one-way latency each step
for k = 1:N
    % ECI position
    nu    = 2*pi * t(k) / Torb;
    r_orb = a * [cos(nu); sin(nu); 0];
    R_inc = [1, 0, 0;
             0, cos(incl), -sin(incl);
             0, sin(incl),  cos(incl)];
    r_eci = R_inc * r_orb;
    % ECEF position
    theta     = omega * t(k);
    R_e       = [ cos(theta),  sin(theta), 0;
                 -sin(theta),  cos(theta), 0;
                          0,           0, 1 ];
    r_ecef    = R_e * r_eci;
    % Vector from GS to sat
    rho        = r_ecef - gs;
    elev(k)    = asin(dot(rho/norm(rho), gs/norm(gs)));  % rad
    latency(k) = norm(rho) / c;                          % s
end

% Detect passes
vis       = elev > 0;
dvis      = diff([0 vis 0]);
starts    = find(dvis==1);
ends      = find(dvis==-1)-1;
durations = (ends - starts + 1) * dt;     % s

% Print per-pass stats (one-way & RTT)
fprintf('\nDaily passes + latency/RTT over Svalbard station:\n');
fprintf('------------------------------------------------\n');
for i = 1:numel(durations)
    L   = latency(starts(i):ends(i)) * 1e3;   % one-way ms
    Rtt = 2 * L;                              % RTT ms
    fprintf('Pass %2d: duration = %.1f min\n', i, durations(i)/60);
    fprintf('   one-way  latency min/avg/max = %.1f/%.1f/%.1f ms\n', ...
            min(L), mean(L), max(L));
    fprintf('   RTT latency       min/avg/max = %.1f/%.1f/%.1f ms\n', ...
            min(Rtt), mean(Rtt), max(Rtt));
end

% Compute and print daily averages
avgDur = mean(durations)/60;                   % min
avgLat = mean(latency(vis)) * 1e3;             % one-way ms
avgRtt = 2 * avgLat;                           % RTT ms
fprintf('------------------------------------------------\n');
fprintf('Total passes : %d\n', numel(durations));
fprintf('Avg duration : %.1f min\n', avgDur);
fprintf('Avg one-way  latency : %.1f ms\n', avgLat);
fprintf('Avg RTT latency       : %.1f ms\n\n', avgRtt);
