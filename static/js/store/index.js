const { configureStore } = window.RTK;

const store = configureStore({
  reducer: {
    profile: window.profileSlice
  }
});

window.store = store;
