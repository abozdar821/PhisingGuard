/** @type {import('next').NextConfig} */
const nextConfig = {
  serverExternalPackages: ['@aws-sdk/client-dynamodb', '@aws-sdk/lib-dynamodb'],
  env: { NEXT_PUBLIC_APP_VERSION: '1.0.0-h01' },
};
export default nextConfig;
