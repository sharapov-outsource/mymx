/**
 * Draws mymx's icons. The tile and the PNG writer live in the service kit;
 * what is here is the glyph — an envelope with the accent on its seal.
 *
 *   node scripts/make-icons.js
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { makeIcons, roundedRect, segment } from '@sharapov/service-kit/make-icons';

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

/** Coordinates are the same 1024-unit grid public/icon.svg is drawn on. */
function glyph(at, x, y) {
  // The seal sits on top of everything.
  if (Math.hypot(x - at(760), y - at(680)) <= at(104)) return 'accent';

  const inEnvelope = roundedRect(x, y, at(512), at(512), at(320), at(200), at(72)) <= 0;
  if (!inEnvelope) return null;

  // The flap is cut back out of the paper, so it reads as a fold.
  const flap = Math.min(
    segment(x, y, at(244), at(372), at(512), at(552)),
    segment(x, y, at(512), at(552), at(780), at(372))
  );
  return flap <= at(28) ? null : 'paper';
}

export { glyph, roundedRect };

makeIcons({ publicDir: PUBLIC_DIR, glyph });
