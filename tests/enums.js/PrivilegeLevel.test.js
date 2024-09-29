const PrivilegeLevel = require('../../src/enums/PrivilegeLevel');

describe('PrivilegeLevel Enumeration', () => {
  it('should be an object with frozen properties', () => {
    expect(typeof PrivilegeLevel === 'object').toBeTruthy();
    expect(Object.prototype.isPrototypeOf.call(Object.getPrototypeOf(PrivilegeLevel), Object))
      .toBeTruthy();
    expect(Object.isFrozen(PrivilegeLevel)).toBeTruthy();
  });

  it('should have the correct property keys', () => {
    const expectedKeys = ['NotAuthenticated', 'Client', 'Administrator', 'InitialAdmin', 'APIToken'];
    expect(Object.keys(PrivilegeLevel)).toEqual(expectedKeys);
  });

  it('should have valid privilege level values', () => {
    const expectedValues = ['NotAuthenticated', 'Client', 'Administrator', 'InitialAdmin', 'APIToken'];
    expect(Object.values(PrivilegeLevel)).toEqual(expectedValues);
  });

  it('should throw an error when accessing an invalid property', () => {
    const unknownProperty = 'Unknown';
    expect(() => PrivilegeLevel[unknownProperty]).toThrow(Error);
    expect(() => PrivilegeLevel[unknownProperty]).toThrow(`'${unknownProperty}' is not a valid privilege level`);
  });

  it('should be case-sensitive when accessing property values', () => {
    const lowerCaseProp = 'notauthenticated';
    const upperCaseProp = 'NOTAUTHENTICATED';
    expect(() => PrivilegeLevel[lowerCaseProp]).toThrow(Error);
    expect(() => PrivilegeLevel[upperCaseProp]).toThrow(Error);
  });
});
