#!/usr/bin/python

# The scripted is a mod version from:

from __future__ import print_function

import os
import re
import sys
import struct
import ntpath
import re
from argparse import ArgumentParser
from io import BytesIO
from tempfile import TemporaryFile
from os.path import basename, dirname, join
from subprocess import Popen, PIPE
try:
    from urllib import urlopen
except ImportError:
    from urllib.request import urlopen

import utils
from utils import SubprocessError, NotFromCDError,\
    AccurateripError, NetworkError

BIN = {'metaflac': None,
       'ffprobe' : 'avprobe',
       'sox'     : None,
       'ckcdda'  : None,
       }

PROGNAME = 'arverify'
VERSION = '0.2'
REQUIRED = ['ffprope', 'sox', 'ckcdda']
PROCS = []

MIN_OFFSET = -2939


# ## Accuraterip Entry
class AccurateripEntry(object):
    """Represents one entry in Accuraterip database. One track
    may have several entries in the database
    """

    def __init__(self, crc, crc450, confidence):
        self.crc = crc
        self.crc450 = crc450
        self.confidence = confidence


# ## Track
class Track(object):
    """One track and its associated metadata/information"""

    def __init__(self, path):
        self.path = path
        self.num_samples = utils.get_num_samples(BIN, path)
        self.num_sectors = int(self.num_samples/588)
        if self.num_samples % 588 != 0:
            msg = "%s not from CD (%i samples)\n" % \
                (path, self.num_samples)
            raise NotFromCDError(msg)
        self.ar_entries = []

        # key is offset, value is list of confidence levels
        self.exact_matches = {}
        self.possible_matches = {}

    @property
    def num_submissions(self):
        return sum([e.confidence for e in self.ar_entries])

    def __matches_summary(self, matches, album_matches):
        total = 0

        for offset in sorted(matches):
            confidence = matches[offset]
            ns = self.num_submissions
            total += 1
            if offset not in album_matches:
                album_matches[offset] = []
            album_matches[offset].append((confidence, ns))
        return total

    def ripsummary(self, album_exact_matches, album_possible_matches, album_not_present, album_not_accurate):

        good = self.__matches_summary(self.exact_matches, album_exact_matches)
        possible = self.__matches_summary(self.possible_matches, album_possible_matches)
        summary = good + possible

        ns = self.num_submissions

        # When there's no submission for the disc id, the rip is considered not present (missing);
        if ns == 0:
            album_not_present.append(0)

        # When no match, the rip is considered to be a bad rip.
        elif not good and not possible:
            album_not_accurate.append(ns)


# ## Process Arguments
def process_arguments():
    parser = \
        ArgumentParser(description='Verify lossless files with accuraterip.',
                       prog=PROGNAME)
    parser.add_argument('paths', metavar='file', nargs='+',
                        type=utils.isfile,
                        help='lossless audio file')
    parser.add_argument("-a", "--additional-sectors",
                        dest="additional_sectors", type=int,
                        help="additional pregap sectors beyond standard 150",
                        default=0,
                        )
    utils.add_common_arguments(parser, VERSION)

    return parser.parse_args()


# ## Scan Files
#
# Untouched.
def scan_files(tracks):
    sox_args = ['sox']+[t.path for t in tracks]+['-t', 'raw', '-']
    entries_per_track = max([len(t.ar_entries) for t in tracks])
    ckcdda_args = [BIN['ckcdda'], entries_per_track]

    for track in tracks:
        ckcdda_args.append(str(track.num_sectors))
        crcs = [e.crc for e in track.ar_entries]
        crc450s = [e.crc450 for e in track.ar_entries]
        crcs += [0]*(entries_per_track-len(crcs))
        crc450s += [0]*(entries_per_track-len(crc450s))
        ckcdda_args += crcs
        ckcdda_args += crc450s

    ckcdda_args = map(str, ckcdda_args)

    tmp = TemporaryFile()
    PROCS.append(Popen(sox_args, stdout=PIPE))
    PROCS.append(Popen(ckcdda_args, stdin=PROCS[-1].stdout, stdout=tmp))

    p = PROCS[-1]
    while p.poll() is None:
        utils.show_status('Calculating checksums for %i files', len(tracks))
    utils.finish_status()

    out, err = p.communicate()
    tmp.seek(0)
    out = tmp.read().decode()
    for pr in PROCS:
        if pr.returncode:
            raise SubprocessError('sox had an error (returned %i)' % pr.returncode)

    lines = out.split('\n')
    num_lines = len(lines)

    results1 = []
    results2 = []
    results450 = []
    for i, line in enumerate(lines):
        if not re.match('^\d', line):
            continue

        index, data = line.split(': ')
        track_index, offset = [int(x) for x in index.split(',')]
        hashes = [int(x, 16) for x in data.split()]

        crc1, crc450 = hashes[:2]
        if len(hashes) > 2:
            crc2 = hashes[2]
        else:
            crc2 = None

        track = tracks[track_index]

        if offset == 0:
            track.crc1 = crc1
            track.crc2 = crc2
            track.crc450 = crc450

        for entry in track.ar_entries:
            if entry.crc in (crc1, crc2):
                if offset not in track.exact_matches:
                    track.exact_matches[offset] = 0
                track.exact_matches[offset] += entry.confidence
            elif entry.crc450 == crc450 and offset != 0:
                if offset not in track.possible_matches:
                    track.possible_matches[offset] = 0
                track.possible_matches[offset] += entry.confidence


# ## Calculate Disc IDs
#
# Untouched.
#
# 1. Handle data track;
# 2. Handle sectors before first track;
# 3. Calculate offsets of all tracks;
# 4. [Algorithm](https://forum.dbpoweramp.com/showthread.php?20641) for disc ids generation.
def get_disc_ids(tracks, additional_sectors=0, data_track_len=0):

    try:
        data_track_len = int(data_track_len)
    except ValueError:
        dt = re.split('[:.]', data_track_len)
        data_track_len = int(dt.pop())
        num_seconds = 0
        multiplier = 1
        while dt:
            num_seconds += multiplier*int(dt.pop())
            multiplier *= 60
        data_track_len += (num_seconds*44100)/588

    track_offsets = [additional_sectors]
    cur_sectors = additional_sectors

    for track in tracks:
        cur_sectors += track.num_sectors
        track_offsets.append(cur_sectors)

    id1, id2, cddb = (0, 0, 0)
    for tracknumber, offset in enumerate(track_offsets, start=1):
        id1 += offset
        id2 += tracknumber * (offset if offset else 1)

    if data_track_len:
        id1 += data_track_len + 11400
        id2 += (data_track_len + 11400)*len(track_offsets)
        track_offsets[-1] += 11400
        track_offsets.append(data_track_len + track_offsets[-1])

    cddb = sum([sum(map(int, str(int(o/75) + 2))) for o in track_offsets[:-1]])
    cddb = ((cddb % 255) << 24) + \
        (int(track_offsets[-1]/75) - int(track_offsets[0]/75) << 8) + \
        len(track_offsets) - 1

    id1 &= 0xFFFFFFFF;
    id2 &= 0xFFFFFFFF;
    cddb &= 0xFFFFFFFF;

    return (cddb, id1, id2)


# ## Fetch AccurateRip Entries
#
# Untouched.
#
# 1. Generate URL;
# 2. Handle `404`;
# 3. Parse binary accuraterip data.
def get_ar_entries(cddb, id1, id2, tracks):
    url = ("http://www.accuraterip.com/accuraterip/%.1x/%.1x/%.1x/dBAR-%.3d-%.8x-%.8x-%.8x.bin")
    url = url % (id1 & 0xF, id1>>4 & 0xF, id1>>8 & 0xF, len(tracks), id1, id2, cddb)
    try:
        data = urlopen(url).read()
    except IOError:
        raise NetworkError("Could not connect to accuraterip database")
    if b'html' in data and b'404' in data:
        data = b''

    return process_binary_ar_entries(BytesIO(bytes(data)), cddb, id1, id2, tracks)


# ## Parse Binary AccurateRip Data
#
# Untouched.
#
# [See](https://forum.dbpoweramp.com/showthread.php?20641)
def process_binary_ar_entries(fdata, cddb, id1, id2, tracks):
    if not fdata:
        return

    trackcount = len(tracks)

    while True:
        chunk_trackcount = fdata.read(1)
        chunk_id1 = fdata.read(4)
        chunk_id2 = fdata.read(4)
        chunk_cddb = fdata.read(4)
        if len(chunk_trackcount) + len(chunk_id1) + len(chunk_id2) + \
                len(chunk_cddb) != 13:
            break

        # unpack as unsigned char
        ar_trackcount = int(struct.unpack('B', chunk_trackcount)[0])

        # unpack as unsigned integers
        ar_id1 = int(struct.unpack('I', chunk_id1)[0])
        ar_id2 = int(struct.unpack('I', chunk_id2)[0])
        ar_cddb = int(struct.unpack('I', chunk_cddb)[0])

        # Ensure it's the disc.
        if ar_trackcount != trackcount or \
                ar_id1 != id1 or ar_id2 != id2 or ar_cddb != cddb:
            raise AccurateripError("Track count or Disc IDs don't match")

        # Associate accurate rip entries for tracks.
        for track in tracks:
            chunk_confidence = fdata.read(1)
            chunk_crc = fdata.read(4)
            chunk_crc450 = fdata.read(4) # skip 4 bytes
            if len(chunk_crc) + len(chunk_confidence) + len(chunk_crc450) != 9:
                break
            confidence = int(struct.unpack('B', chunk_confidence)[0])
            crc = int(struct.unpack('I', chunk_crc)[0])
            crc450 = int(struct.unpack('I', chunk_crc450)[0])
            track.ar_entries.append(AccurateripEntry(crc, crc450, confidence))


# ## Print Summary
def print_summary(tracks):

    # Separating line between disc id and tracks.
    print('-' * 31)

    # Matches.
    good  = {}    # Matching main CRC (with or without offset)
    maybe = {}    # main CRC mismatch and CRC450 match
    bad   = []    # main CRC mismatch and no CRC450 match
    np    = []    # No accuraterip data at all

    # Process all tracks.
    for track in tracks:
        track.ripsummary(good, maybe, np, bad)

    trackcount = len(tracks)
    offset = []

    # Output good / maybe conclusion line.
    def conclusion(category, offsets):
        def cmp(x, y):
            x = offsets[x]
            y = offsets[y]
            len_diff = len(y) - len(x)
            if len_diff: return len_diff
            elif sum([entry[0] for entry in x]) < sum([entry[0] for entry in y]): return 1
            else: return -1
        offset[:] = [sorted(offsets, cmp=cmp)[0]]
        entries = offsets[offset[0]]
        num_matches = len(entries)
        confidence, num_submissions = max(entries, key=lambda entry: entry[0])
        return '%i/%i %s %i %i %i' % (num_matches, trackcount, category, offset[0], confidence, num_submissions)

    # Output one line conclusion.
    disc_conclusion = (
      conclusion('A', good) if good else
      conclusion('P', maybe) if maybe else
      '%i/%i N' % (len(np), trackcount) if np else
      '%i/%i B' % (len(bad), trackcount))

    # Output track info:
    #
    # `01 F4974593 17AC665E C826BEF5 A`
    #
    # 1. 2-digits track number;
    # 2. crc v1;
    # 3. crc v2;
    # 4. crc of 450 frames;
    # 5. track conclusion:
    #    + `A` for accurate rip;
    #    + `P` for tracks may pop;
    #    + `N` for new tracks;
    #    + `B` for bad rips.
    for track in tracks:
        track_number = re.search('\d{2}', ntpath.basename(track.path)).group(0)
        info = [track_number] + map((lambda crc: '%08X' % crc), [
            track.crc1,
            track.crc2,
            track.crc450
        ])
        if offset: info.append(
            'A' if track.exact_matches[offset[0]] else
            'P' if track.possible_matches[offset[0]] else
            'N' if track.num_submissions == 0 else
            'B')
        print(' '.join(info))

    # Separator line between disc conclusion and tracks.
    print('=' * 31)

    # Output disc conclusion
    print(disc_conclusion)


# ## Main
#
# 1. Check dependencies;
# 2. Construct tracks;
# 3. Calculate disc ids;
# 4. Print accuraterip disc id and additional frames;
# 5. Fetch accuraterip entries;
# 6. Checksum tracks;
# 7. Output matches.
def main(options):
    utils.check_dependencies(BIN, REQUIRED)
    tracks = map(Track, options.paths)
    cddb, id1, id2 = get_disc_ids(tracks, options.additional_sectors)
    print('%08x-%08x-%08x %i' % (id1, id2, cddb, options.additional_sectors))
    get_ar_entries(cddb, id1, id2, tracks)
    scan_files(tracks)
    print_summary(tracks)


if __name__ == '__main__':
    utils.execute(main, process_arguments, PROCS)
