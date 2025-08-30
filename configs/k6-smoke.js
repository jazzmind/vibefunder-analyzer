import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 5,
  duration: '30s',
  thresholds: {
    http_req_duration: ['p(95)<500']
  }
};

export default function () {
  const res = http.get(__ENV.K6_TARGET || 'http://sample_app:3000/health');
  check(res, { 'status was 200': (r) => r.status === 200 });
  sleep(1);
}
