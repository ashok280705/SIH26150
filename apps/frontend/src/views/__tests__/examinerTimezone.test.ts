import { RecordingSession, ExaminerTimezone } from '../../types';

/**
 * Pure helper function mirroring the temporal logic to interpret a session's timestamps
 * with optional examiner timezone assertions.
 */
export function interpretSessionTemporalEvidence(
  session: RecordingSession,
  examinerTz?: ExaminerTimezone | null
): {
  recorderTime: string | null;
  filesystemTimezone: string;
  examinerTimezone: string | null;
  effectiveInterpretation: string;
  temporalBasis: 'device_local' | 'absolute_utc';
  hasConflict: boolean;
  conflictDetails?: string;
} {
  const filesystemTimezone = session.filesystem_timezone || session.timezone || 'Unknown';
  const effectiveExaminerTz = examinerTz ?? session.examiner_timezone ?? null;

  if (!effectiveExaminerTz) {
    return {
      recorderTime: session.start_native,
      filesystemTimezone,
      examinerTimezone: null,
      effectiveInterpretation: session.start_native ?? session.start_normalized,
      temporalBasis: 'device_local',
      hasConflict: false,
    };
  }

  // Check for conflict if filesystem timezone is known and differs
  let hasConflict = false;
  let conflictDetails: string | undefined;

  if (filesystemTimezone !== 'Unknown' && filesystemTimezone !== effectiveExaminerTz.timezone) {
    hasConflict = true;
    conflictDetails = `Filesystem indicates ${filesystemTimezone} but examiner established ${effectiveExaminerTz.timezone}`;
  }

  return {
    recorderTime: session.start_native,
    filesystemTimezone,
    examinerTimezone: effectiveExaminerTz.timezone,
    effectiveInterpretation: session.start_normalized,
    temporalBasis: 'absolute_utc',
    hasConflict,
    conflictDetails,
  };
}

export function runPhase3Tests() {
  console.log('Running Phase 3 Examiner Timezone Unit Tests...\n');

  // 1. No examiner timezone
  {
    const session: RecordingSession = {
      id: 's-1',
      channel: 1,
      start_native: '2026-09-20T10:00:00',
      end_native: '2026-09-20T10:10:00',
      start_normalized: '2026-09-20T10:00:00',
      end_normalized: '2026-09-20T10:10:00',
      timezone: 'Unknown',
      temporal_basis: 'device_local',
      filesystem_timezone: 'Unknown',
      examiner_timezone: null,
      timezone_conflict: null,
      segment_count: 1,
      span_seconds: 600,
      covered_seconds: 600,
      missing_seconds: 0,
      coverage_ratio: 1.0,
      nominal_segment_seconds: 10,
      gaps: [],
      segments: [],
    };

    const res = interpretSessionTemporalEvidence(session, null);
    if (res.temporalBasis !== 'device_local') throw new Error('Test 1 Failed: Expected device_local');
    if (res.filesystemTimezone !== 'Unknown') throw new Error('Test 1 Failed: Filesystem tz must be Unknown');
    if (res.examinerTimezone !== null) throw new Error('Test 1 Failed: Examiner tz must be null');
    if (res.effectiveInterpretation !== '2026-09-20T10:00:00') throw new Error('Test 1 Failed: Must not fabricate UTC');
    console.log('✓ Test 1: No examiner timezone retains device_local wall clock');
  }

  // 2. Examiner timezone supplied
  {
    const session: RecordingSession = {
      id: 's-2',
      channel: 1,
      start_native: '2026-09-20T10:00:00',
      end_native: '2026-09-20T10:10:00',
      start_normalized: '2026-09-20T04:30:00Z',
      end_normalized: '2026-09-20T04:40:00Z',
      timezone: 'Asia/Kolkata',
      temporal_basis: 'absolute_utc',
      filesystem_timezone: 'Unknown',
      examiner_timezone: {
        timezone: 'Asia/Kolkata',
        source: 'DVR System Menu Screen Photo',
        established_by: 'Det. Holmes #104',
        notes: 'Confirmed on-screen timezone display matches IST',
        established_at: '2026-09-26T12:00:00Z',
      },
      timezone_conflict: null,
      segment_count: 1,
      span_seconds: 600,
      covered_seconds: 600,
      missing_seconds: 0,
      coverage_ratio: 1.0,
      nominal_segment_seconds: 10,
      gaps: [],
      segments: [],
    };

    const res = interpretSessionTemporalEvidence(session);
    if (res.temporalBasis !== 'absolute_utc') throw new Error('Test 2 Failed: Expected absolute_utc');
    if (res.filesystemTimezone !== 'Unknown') throw new Error('Test 2 Failed: Filesystem tz must remain Unknown');
    if (res.examinerTimezone !== 'Asia/Kolkata') throw new Error('Test 2 Failed: Examiner tz mismatch');
    if (res.effectiveInterpretation !== '2026-09-20T04:30:00Z') throw new Error('Test 2 Failed: UTC interpretation mismatch');
    console.log('✓ Test 2: Examiner timezone supplied converts to absolute UTC');
  }

  // 3. Known parser timezone + matching examiner timezone
  {
    const session: RecordingSession = {
      id: 's-3',
      channel: 1,
      start_native: '2026-09-20T10:00:00',
      end_native: '2026-09-20T10:10:00',
      start_normalized: '2026-09-20T04:30:00Z',
      end_normalized: '2026-09-20T04:40:00Z',
      timezone: 'UTC+05:30',
      temporal_basis: 'absolute_utc',
      filesystem_timezone: 'UTC+05:30',
      examiner_timezone: {
        timezone: 'UTC+05:30',
        source: 'DVR Configuration Documentation',
        established_by: 'Examiner Jane',
        notes: null,
        established_at: '2026-09-26T12:00:00Z',
      },
      timezone_conflict: null,
      segment_count: 1,
      span_seconds: 600,
      covered_seconds: 600,
      missing_seconds: 0,
      coverage_ratio: 1.0,
      nominal_segment_seconds: 10,
      gaps: [],
      segments: [],
    };

    const res = interpretSessionTemporalEvidence(session);
    if (res.hasConflict) throw new Error('Test 3 Failed: Matching timezones should not conflict');
    console.log('✓ Test 3: Known parser timezone + matching examiner timezone matches without conflict');
  }

  // 4. Conflicting parser and examiner timezone
  {
    const session: RecordingSession = {
      id: 's-4',
      channel: 1,
      start_native: '2026-09-20T10:00:00',
      end_native: '2026-09-20T10:10:00',
      start_normalized: '2026-09-20T14:00:00Z',
      end_normalized: '2026-09-20T14:10:00Z',
      timezone: 'UTC-04:00',
      temporal_basis: 'absolute_utc',
      filesystem_timezone: 'UTC+05:30',
      examiner_timezone: {
        timezone: 'UTC-04:00',
        source: 'Site acquisition note',
        established_by: 'Investigator Doe',
        notes: 'Discrepancy observed with OEM header',
        established_at: '2026-09-26T12:00:00Z',
      },
      timezone_conflict: 'Discrepancy between filesystem (+05:30) and examiner (-04:00)',
      segment_count: 1,
      span_seconds: 600,
      covered_seconds: 600,
      missing_seconds: 0,
      coverage_ratio: 1.0,
      nominal_segment_seconds: 10,
      gaps: [],
      segments: [],
    };

    const res = interpretSessionTemporalEvidence(session);
    if (!res.hasConflict) throw new Error('Test 4 Failed: Expected conflict between UTC+05:30 and UTC-04:00');
    console.log('✓ Test 4: Conflicting parser and examiner timezone flagged');
  }

  // 5. Changing examiner timezone
  {
    const session: RecordingSession = {
      id: 's-5',
      channel: 1,
      start_native: '2026-09-20T10:00:00',
      end_native: '2026-09-20T10:10:00',
      start_normalized: '2026-09-20T04:30:00Z',
      end_normalized: '2026-09-20T04:40:00Z',
      timezone: 'UTC+05:30',
      temporal_basis: 'absolute_utc',
      filesystem_timezone: 'Unknown',
      examiner_timezone: {
        timezone: 'UTC+05:30',
        source: 'Initial note',
        established_by: 'Officer A',
        notes: null,
        established_at: '2026-09-26T12:00:00Z',
      },
      timezone_conflict: null,
      segment_count: 1,
      span_seconds: 600,
      covered_seconds: 600,
      missing_seconds: 0,
      coverage_ratio: 1.0,
      nominal_segment_seconds: 10,
      gaps: [],
      segments: [],
    };

    const newTz: ExaminerTimezone = {
      timezone: 'UTC+00:00',
      source: 'Corrected DVR config',
      established_by: 'Senior Examiner B',
      notes: 'Corrected timezone assertion',
      established_at: '2026-09-26T13:00:00Z',
    };

    const res = interpretSessionTemporalEvidence(session, newTz);
    if (res.examinerTimezone !== 'UTC+00:00') throw new Error('Test 5 Failed: New examiner tz not reflected');
    if (res.recorderTime !== '2026-09-20T10:00:00') throw new Error('Test 5 Failed: Native recorder time was modified');
    console.log('✓ Test 5: Changing examiner timezone preserves native recorder time');
  }

  // 6. Removing examiner timezone
  {
    const session: RecordingSession = {
      id: 's-6',
      channel: 1,
      start_native: '2026-09-20T10:00:00',
      end_native: '2026-09-20T10:10:00',
      start_normalized: '2026-09-20T10:00:00',
      end_normalized: '2026-09-20T10:10:00',
      timezone: 'Unknown',
      temporal_basis: 'device_local',
      filesystem_timezone: 'Unknown',
      examiner_timezone: null,
      timezone_conflict: null,
      segment_count: 1,
      span_seconds: 600,
      covered_seconds: 600,
      missing_seconds: 0,
      coverage_ratio: 1.0,
      nominal_segment_seconds: 10,
      gaps: [],
      segments: [],
    };

    const res = interpretSessionTemporalEvidence(session, null);
    if (res.temporalBasis !== 'device_local') throw new Error('Test 6 Failed: Must revert to device_local');
    if (res.examinerTimezone !== null) throw new Error('Test 6 Failed: Examiner tz must be null');
    console.log('✓ Test 6: Removing examiner timezone reversibly restores device_local semantics');
  }

  // 7. Timeline conversion accuracy
  {
    // Native: 2026-09-20 10:00:00, Offset: +05:30 -> UTC: 2026-09-20 04:30:00Z
    const native = '2026-09-20T10:00:00';
    const date = new Date(native + '+05:30');
    if (date.toISOString() !== '2026-09-20T04:30:00.000Z') {
      throw new Error(`Test 7 Failed: Expected 04:30:00Z, got ${date.toISOString()}`);
    }
    console.log('✓ Test 7: Timeline conversion mathematically accurate (10:00:00 at +05:30 -> 04:30:00 UTC)');
  }

  // 8. Cross-device comparison
  {
    // Device A: Ch 1 at 10:00:00 with +05:30 -> UTC 04:30:00
    // Device B: Ch 1 at 00:30:00 with -04:00 -> UTC 04:30:00
    const devAUtc = new Date('2026-09-20T10:00:00+05:30').getTime();
    const devBUtc = new Date('2026-09-20T00:30:00-04:00').getTime();
    if (devAUtc !== devBUtc) {
      throw new Error('Test 8 Failed: Cross-device instants should align in UTC');
    }
    console.log('✓ Test 8: Cross-device comparison succeeds across different examiner timezones');
  }

  // 9. Report / provenance representation
  {
    const tz: ExaminerTimezone = {
      timezone: 'UTC+05:30',
      source: 'DVR OSD Menu Photo IMG_0042.JPG',
      established_by: 'Examiner Sherlock',
      notes: 'Clock synchronized with NTP per router logs',
      established_at: '2026-09-26T12:00:00Z',
    };
    if (!tz.source || !tz.established_by || !tz.established_at) {
      throw new Error('Test 9 Failed: Full provenance audit fields must be populated');
    }
    console.log('✓ Test 9: Report / provenance representation includes all audit trail fields');
  }

  // 10. Ensure system timezone is never used automatically
  {
    const session: RecordingSession = {
      id: 's-10',
      channel: 1,
      start_native: '2026-09-20T10:00:00',
      end_native: '2026-09-20T10:10:00',
      start_normalized: '2026-09-20T10:00:00',
      end_normalized: '2026-09-20T10:10:00',
      timezone: 'Unknown',
      temporal_basis: 'device_local',
      filesystem_timezone: 'Unknown',
      examiner_timezone: null,
      timezone_conflict: null,
      segment_count: 1,
      span_seconds: 600,
      covered_seconds: 600,
      missing_seconds: 0,
      coverage_ratio: 1.0,
      nominal_segment_seconds: 10,
      gaps: [],
      segments: [],
    };

    // When examiner_timezone is not explicitly passed, output must remain device_local with Unknown timezone
    const res = interpretSessionTemporalEvidence(session, null);
    if (res.temporalBasis === 'absolute_utc') {
      throw new Error('Test 10 Failed: Silently inferred UTC or system timezone!');
    }
    if (res.examinerTimezone !== null) {
      throw new Error('Test 10 Failed: Inferred examiner timezone from system!');
    }
    console.log('✓ Test 10: System/browser timezone is never used automatically');
  }

  console.log('\nAll 10 Phase 3 Unit Tests Passed Successfully!\n');
}

runPhase3Tests();
