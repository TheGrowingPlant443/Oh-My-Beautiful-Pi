import { cp, mkdir, readFile, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// Keep all native cache writes inside the fixture. A source SDK loads its bundled
// platform addon directly (and stages it here on Windows), so a populated user
// cache is not a prerequisite. Retain an existing version-matched cache for
// installations that need it; missing addons still fail in the real SDK loader.
export async function prepareSdkNatives(sdk, root) {
  const nativeRoot = path.join(root, 'natives');
  await mkdir(nativeRoot, { recursive: true });
  const { version } = JSON.parse(await readFile(path.join(sdk, 'package.json'), 'utf8'));
  const source = path.join(process.env.PI_NATIVES_DIR || path.join(os.homedir(), '.omp', 'natives'), version);
  try {
    await stat(source);
  } catch (error) {
    if (error.code === 'ENOENT') return nativeRoot;
    throw error;
  }
  await cp(source, path.join(nativeRoot, version), { recursive: true });
  return nativeRoot;
}
