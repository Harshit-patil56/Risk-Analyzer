export async function GET() {
  return Response.json(
    { status: "ok", service: "risk-analyzer-frontend" },
    { status: 200 }
  );
}

export async function HEAD() {
  return new Response(null, { status: 200 });
}
