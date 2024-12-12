// Initialize Redux store
window.store = window.RTK.configureStore({
  reducer: {
    profile: window.profileReducer
  }
});
