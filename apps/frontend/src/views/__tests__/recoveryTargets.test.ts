import { buildRecoveryTargets } from '../RecoveryView';
import { RecordingSession, GapAnalysis } from '../../types';

function createMockSession(
  channel: number,
  gaps: Array<{ previous_offset: number; previous_length: number; next_offset: number; missing_seconds: number }>
): RecordingSession {
  return {
    id: `session-ch${channel}`,
    channel,
    start_native: '2026-09-20T10:00:00',
    end_native: '2026-09-20T11:00:00',
    start_normalized: '2026-09-20T10:00:00',
    end_normalized: '2026-09-20T11:00:00',
    timezone: 'Unknown',
    temporal_basis: 'device_local',
    segment_count: 5,
    span_seconds: 3600,
    covered_seconds: 3000,
    missing_seconds: 600,
    coverage_ratio: 0.833,
    nominal_segment_seconds: 10,
    gaps: gaps.map((g, i) => ({
      starts_after_native: '2026-09-20T10:10:00',
      ends_before_native: '2026-09-20T10:20:00',
      starts_after_normalized: '2026-09-20T10:10:00',
      ends_before_normalized: '2026-09-20T10:20:00',
      missing_seconds: g.missing_seconds,
      previous_offset: g.previous_offset,
      previous_length: g.previous_length,
      next_offset: g.next_offset,
      reason: `Gap ${i} missing footage`,
    })),
    segments: [],
  };
}

function createMockGapAnalysis(
  unaccountedRegions: Array<{ offset: number; length: number; reason?: string }>
): GapAnalysis {
  return {
    temporal_gaps: [],
    coverage: {
      total_bytes: 10000000,
      accounted_bytes: 2000000,
      unaccounted_bytes: 8000000,
      coverage_ratio: 0.2,
      unaccounted_regions: unaccountedRegions.map((r, i) => ({
        region: { offset: r.offset, length: r.length },
        reason: r.reason || `Unaccounted span ${i}`,
      })),
    },
    events_with_unknown_timezone: 0,
    events_without_normalized_time: 0,
    gaps_present: unaccountedRegions.length > 0,
    validation: {
      state: 'PASS',
      reason: 'Valid',
      operation: 'test',
      subject: 'coverage',
    },
  };
}

function runTests() {
  console.log('Running Recovery Targets Unit Tests...');

  // 1. Only temporal gaps exist
  {
    const sessions = [createMockSession(1, [{ previous_offset: 1000, previous_length: 500, next_offset: 2000, missing_seconds: 30 }])];
    const gapAnalysis = createMockGapAnalysis([]);
    const targets = buildRecoveryTargets(sessions, gapAnalysis);

    if (targets.length !== 1) throw new Error(`Test 1 Failed: Expected 1 target, got ${targets.length}`);
    if (targets[0].targetType !== 'temporal_gap') throw new Error(`Test 1 Failed: Expected temporal_gap, got ${targets[0].targetType}`);
    if (targets[0].scanStart !== 1500) throw new Error(`Test 1 Failed: scanStart mismatch`);
    if (targets[0].scanEnd !== 2000) throw new Error(`Test 1 Failed: scanEnd mismatch`);
    console.log('✓ Test 1: Only temporal gaps exist passed');
  }

  // 2. Only physical unaccounted regions exist
  {
    const sessions = [createMockSession(1, [])];
    const gapAnalysis = createMockGapAnalysis([{ offset: 0x418000, length: 0x200000 }]);
    const targets = buildRecoveryTargets(sessions, gapAnalysis);

    if (targets.length !== 1) throw new Error(`Test 2 Failed: Expected 1 target, got ${targets.length}`);
    if (targets[0].targetType !== 'physical_unaccounted') throw new Error(`Test 2 Failed: Expected physical_unaccounted`);
    if (targets[0].scanStart !== 0x418000) throw new Error(`Test 2 Failed: scanStart mismatch`);
    if (targets[0].scanEnd !== 0x618000) throw new Error(`Test 2 Failed: scanEnd mismatch`);
    if (targets[0].length !== 0x200000) throw new Error(`Test 2 Failed: length mismatch`);
    console.log('✓ Test 2: Only physical unaccounted regions exist passed');
  }

  // 3. Both exist
  {
    const sessions = [createMockSession(1, [{ previous_offset: 1000, previous_length: 200, next_offset: 1500, missing_seconds: 20 }])];
    const gapAnalysis = createMockGapAnalysis([{ offset: 5000, length: 10000 }]);
    const targets = buildRecoveryTargets(sessions, gapAnalysis);

    if (targets.length !== 2) throw new Error(`Test 3 Failed: Expected 2 targets, got ${targets.length}`);
    const types = targets.map((t) => t.targetType);
    if (!types.includes('temporal_gap') || !types.includes('physical_unaccounted')) {
      throw new Error(`Test 3 Failed: Expected both temporal_gap and physical_unaccounted`);
    }
    console.log('✓ Test 3: Both exist passed');
  }

  // 4. Neither exists
  {
    const sessions = [createMockSession(1, [])];
    const gapAnalysis = createMockGapAnalysis([]);
    const targets = buildRecoveryTargets(sessions, gapAnalysis);

    if (targets.length !== 0) throw new Error(`Test 4 Failed: Expected 0 targets, got ${targets.length}`);
    console.log('✓ Test 4: Neither exists passed');
  }

  // 5. Unknown timezone recordings exist but physical regions are still available
  {
    const session = createMockSession(1, []);
    session.timezone = 'Unknown';
    session.temporal_basis = 'device_local';
    const gapAnalysis = createMockGapAnalysis([{ offset: 0x100000, length: 0x50000 }]);
    const targets = buildRecoveryTargets([session], gapAnalysis);

    if (targets.length !== 1) throw new Error(`Test 5 Failed: Expected 1 target, got ${targets.length}`);
    if (targets[0].targetType !== 'physical_unaccounted') throw new Error(`Test 5 Failed: Target must be physical_unaccounted`);
    console.log('✓ Test 5: Unknown timezone recordings exist but physical regions available passed');
  }

  // 6. Multiple physical regions
  {
    const sessions = [createMockSession(1, [])];
    const gapAnalysis = createMockGapAnalysis([
      { offset: 0x1000, length: 0x500 },
      { offset: 0x5000, length: 0x2000 },
      { offset: 0x9000, length: 0x1000 },
    ]);
    const targets = buildRecoveryTargets(sessions, gapAnalysis);

    if (targets.length !== 3) throw new Error(`Test 6 Failed: Expected 3 targets, got ${targets.length}`);
    console.log('✓ Test 6: Multiple physical regions passed');
  }

  // 7. Region ordering
  {
    const sessions = [createMockSession(1, [{ previous_offset: 8000, previous_length: 500, next_offset: 9000, missing_seconds: 10 }])];
    const gapAnalysis = createMockGapAnalysis([
      { offset: 12000, length: 3000 },
      { offset: 2000, length: 1000 },
    ]);
    const targets = buildRecoveryTargets(sessions, gapAnalysis);

    if (targets.length !== 3) throw new Error(`Test 7 Failed: Expected 3 targets`);
    for (let i = 0; i < targets.length - 1; i++) {
      if (targets[i].scanStart > targets[i + 1].scanStart) {
        throw new Error(`Test 7 Failed: Targets not ordered by scanStart (${targets[i].scanStart} > ${targets[i + 1].scanStart})`);
      }
    }
    console.log('✓ Test 7: Region ordering passed');
  }

  // 8. Region offset/length preservation
  {
    const offset = 0xabcdef;
    const length = 0x12345;
    const sessions = [createMockSession(1, [])];
    const gapAnalysis = createMockGapAnalysis([{ offset, length, reason: 'Test preservation' }]);
    const targets = buildRecoveryTargets(sessions, gapAnalysis);

    if (targets[0].scanStart !== offset) throw new Error(`Test 8 Failed: scanStart not preserved`);
    if (targets[0].scanEnd !== offset + length) throw new Error(`Test 8 Failed: scanEnd not preserved`);
    if (targets[0].length !== length) throw new Error(`Test 8 Failed: length not preserved`);
    if (targets[0].reason !== 'Test preservation') throw new Error(`Test 8 Failed: reason not preserved`);
    console.log('✓ Test 8: Region offset/length preservation passed');
  }

  // 9. No false "No gaps detected" message condition
  {
    // Dahua sample case: 0 session gaps, but physical unaccounted regions exist
    const sessions = [createMockSession(1, [])];
    const gapAnalysis = createMockGapAnalysis([{ offset: 0x217800, length: 17011283 }]);
    const targets = buildRecoveryTargets(sessions, gapAnalysis);

    // If targets > 0, UI will render the table of candidates rather than the "No gaps detected" empty state!
    if (targets.length === 0) {
      throw new Error(`Test 9 Failed: False empty state! targets.length is 0 when physical regions exist`);
    }
    console.log('✓ Test 9: No false "No gaps detected" message condition passed');
  }

  console.log('ALL 9 RECOVERY TARGET TESTS PASSED SUCCESSFULLY!');
}

runTests();
