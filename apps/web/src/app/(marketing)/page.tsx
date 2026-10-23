import { Nav } from "@/components/marketing/nav";
import { Hero } from "@/components/marketing/hero";
import { Surfaces } from "@/components/marketing/surfaces";
import { Security } from "@/components/marketing/security";
import { CliSection } from "@/components/marketing/cli";
import { Comparison } from "@/components/marketing/comparison";
import { Pricing } from "@/components/marketing/pricing";
import { Footer } from "@/components/marketing/footer";

export default function LandingPage() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <Surfaces />
        <Security />
        <CliSection />
        <Comparison />
        <Pricing />
      </main>
      <Footer />
    </>
  );
}
