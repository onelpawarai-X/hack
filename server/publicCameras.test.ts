import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseOsmMapXml } from './publicCameras.ts';

const FIXTURE = `<?xml version="1.0" encoding="UTF-8"?>
<osm version="0.6">
  <node id="1" lat="52.5201" lon="13.4051">
    <tag k="man_made" v="surveillance"/>
    <tag k="surveillance:type" v="outdoor"/>
    <tag k="operator" v="City Safety"/>
    <tag k="contact:webcam" v="https://camera.example/street.m3u8"/>
  </node>
  <node id="2" lat="52.5202" lon="13.4052">
    <tag k="man_made" v="surveillance"/>
    <tag k="camera:type" v="doorbell"/>
    <tag k="name" v="Private doorbell"/>
  </node>
  <node id="3" lat="52.5203" lon="13.4053">
    <tag k="amenity" v="bench"/>
  </node>
  <node id="6" lat="52.5204" lon="13.4054">
    <tag k="man_made" v="surveillance"/>
    <tag k="surveillance" v="indoor"/>
    <tag k="operator" v="Shop interior"/>
  </node>
  <node id="7" lat="52.5205" lon="13.4055">
    <tag k="man_made" v="surveillance"/>
    <tag k="surveillance" v="outdoor"/>
    <tag k="name" v="Public webcam"/>
    <tag k="contact:webcam" v="https://www.youtube.com/watch?v=1-iS7LArMPA"/>
  </node>
  <node id="4" lat="52.5210" lon="13.4060"/>
  <node id="5" lat="52.5220" lon="13.4070"/>
  <way id="10">
    <nd ref="4"/>
    <nd ref="5"/>
    <tag k="man_made" v="surveillance"/>
    <tag k="surveillance:type" v="traffic"/>
    <tag k="operator" v="Traffic Authority"/>
  </way>
</osm>`;

test('parseOsmMapXml keeps public surveillance and drops private doorbells', () => {
  const cameras = parseOsmMapXml(FIXTURE, 52.52, 13.405, 0.5);
  assert.equal(cameras.length, 3);
  assert.equal(cameras[0].id, 'node/1');
  assert.equal(cameras[0].protocol, 'hls');
  assert.equal(cameras[0].operator, 'City Safety');
  const way = cameras.find((camera) => camera.id === 'way/10');
  assert.ok(way);
  assert.equal(way.kind, 'traffic');
  assert.ok(way.distanceKm > 0);
  const youtube = cameras.find((camera) => camera.name === 'Public webcam');
  assert.equal(youtube?.protocol, 'iframe');
  assert.equal(youtube?.streamUrl, 'https://www.youtube.com/embed/1-iS7LArMPA');
  assert.ok(cameras.every((camera) => !/doorbell/i.test(camera.name)));
  assert.ok(cameras.every((camera) => camera.attribution.includes('OpenStreetMap')));
});
