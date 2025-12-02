/**
 * Setup Verification Script
 * Run this to verify your backend installation is correct
 * 
 * Usage: node verify-setup.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('\n🔍 Verifying Backend Setup...\n');

let errors = 0;
let warnings = 0;

// Check Node.js version
console.log('✓ Checking Node.js version...');
const nodeVersion = process.version;
const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
if (majorVersion < 18) {
  console.log(`  ❌ Node.js v${majorVersion} detected. Required: v18+`);
  errors++;
} else {
  console.log(`  ✅ Node.js ${nodeVersion}`);
}

// Check package.json
console.log('\n✓ Checking package.json...');
try {
  const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  console.log(`  ✅ Project: ${packageJson.name} v${packageJson.version}`);
  
  // Check required dependencies
  const requiredDeps = [
    'express', 'mongoose', 'socket.io', 'dotenv', 'bcrypt',
    'jsonwebtoken', 'cors', 'helmet', 'express-rate-limit',
    'express-validator', 'winston'
  ];
  
  const missingDeps = requiredDeps.filter(dep => !packageJson.dependencies[dep]);
  if (missingDeps.length > 0) {
    console.log(`  ❌ Missing dependencies: ${missingDeps.join(', ')}`);
    errors++;
  } else {
    console.log(`  ✅ All required dependencies present`);
  }
} catch (err) {
  console.log(`  ❌ package.json not found or invalid`);
  errors++;
}

// Check directory structure
console.log('\n✓ Checking directory structure...');
const requiredDirs = [
  'server',
  'server/config',
  'server/controllers',
  'server/routes',
  'server/models',
  'server/sockets',
  'server/middlewares',
  'server/utils',
  'server/logs'
];

requiredDirs.forEach(dir => {
  if (fs.existsSync(dir)) {
    console.log(`  ✅ ${dir}/`);
  } else {
    console.log(`  ❌ ${dir}/ - NOT FOUND`);
    errors++;
  }
});

// Check required files
console.log('\n✓ Checking required files...');
const requiredFiles = [
  'server/server.js',
  'server/config/db.js',
  'server/config/corsConfig.js',
  'server/config/rateLimitConfig.js',
  'server/models/User.js',
  'server/models/Message.js',
  'server/models/FileChunk.js',
  'server/models/Log.js',
  'server/controllers/authController.js',
  'server/controllers/messageController.js',
  'server/controllers/fileController.js',
  'server/routes/authRoutes.js',
  'server/routes/messageRoutes.js',
  'server/routes/fileRoutes.js',
  'server/middlewares/authMiddleware.js',
  'server/middlewares/loggingMiddleware.js',
  'server/middlewares/validationMiddleware.js',
  'server/sockets/chatSocket.js',
  'server/utils/logger.js',
  'server/utils/jwtUtils.js',
  'server/utils/validation.js'
];

requiredFiles.forEach(file => {
  if (fs.existsSync(file)) {
    console.log(`  ✅ ${file}`);
  } else {
    console.log(`  ❌ ${file} - NOT FOUND`);
    errors++;
  }
});

// Check .env file
console.log('\n✓ Checking environment configuration...');
if (fs.existsSync('.env')) {
  console.log(`  ✅ .env file exists`);
  
  const envContent = fs.readFileSync('.env', 'utf8');
  const requiredEnvVars = [
    'PORT',
    'MONGODB_URI',
    'JWT_SECRET',
    'JWT_EXPIRE',
    'CORS_ORIGIN'
  ];
  
  requiredEnvVars.forEach(envVar => {
    if (envContent.includes(`${envVar}=`)) {
      console.log(`  ✅ ${envVar} configured`);
    } else {
      console.log(`  ⚠️  ${envVar} not found in .env`);
      warnings++;
    }
  });
  
  // Check if JWT_SECRET is default
  if (envContent.includes('JWT_SECRET=infosec_jwt_secret_key_change_this_in_production')) {
    console.log(`  ⚠️  JWT_SECRET is using default value (change for production!)`);
    warnings++;
  }
} else {
  console.log(`  ⚠️  .env file not found - using environment variables`);
  warnings++;
}

// Check documentation
console.log('\n✓ Checking documentation...');
const docFiles = [
  'README.md',
  'SETUP.md',
  'API_EXAMPLES.md',
  'PROJECT_SUMMARY.md',
  'QUICK_REFERENCE.md'
];

docFiles.forEach(file => {
  if (fs.existsSync(file)) {
    console.log(`  ✅ ${file}`);
  } else {
    console.log(`  ⚠️  ${file} - NOT FOUND`);
    warnings++;
  }
});

// Check node_modules
console.log('\n✓ Checking dependencies installation...');
if (fs.existsSync('node_modules')) {
  console.log(`  ✅ node_modules/ exists`);
  
  // Check if key packages are installed
  const keyPackages = ['express', 'mongoose', 'socket.io'];
  keyPackages.forEach(pkg => {
    if (fs.existsSync(`node_modules/${pkg}`)) {
      console.log(`  ✅ ${pkg} installed`);
    } else {
      console.log(`  ❌ ${pkg} not installed - run 'npm install'`);
      errors++;
    }
  });
} else {
  console.log(`  ❌ node_modules/ not found - run 'npm install'`);
  errors++;
}

// Summary
console.log('\n' + '='.repeat(50));
console.log('📊 Verification Summary');
console.log('='.repeat(50));

if (errors === 0 && warnings === 0) {
  console.log('✅ All checks passed! Setup is complete.');
  console.log('\n🚀 Next steps:');
  console.log('   1. Ensure MongoDB is running');
  console.log('   2. Run: npm run dev');
  console.log('   3. Test: curl http://localhost:5000/health');
} else {
  if (errors > 0) {
    console.log(`❌ ${errors} error(s) found`);
  }
  if (warnings > 0) {
    console.log(`⚠️  ${warnings} warning(s) found`);
  }
  
  console.log('\n🔧 Actions required:');
  if (errors > 0) {
    console.log('   - Fix errors listed above');
    if (!fs.existsSync('node_modules')) {
      console.log('   - Run: npm install');
    }
  }
  if (warnings > 0 && !fs.existsSync('.env')) {
    console.log('   - Create .env file (see SETUP.md)');
  }
}

console.log('\n📚 Documentation:');
console.log('   - README.md - Complete documentation');
console.log('   - SETUP.md - Setup instructions');
console.log('   - API_EXAMPLES.md - API testing examples');
console.log('   - QUICK_REFERENCE.md - Quick reference card');

console.log('\n');

process.exit(errors > 0 ? 1 : 0);

