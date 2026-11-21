declare module 'tlsh' {
  export default class Tlsh {
    update(buffer: Buffer): void;
    final(): void;
    toString(): string;
  }
}
